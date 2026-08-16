! routing_score.f90 — EWMA RTT + failure penalty + DNSSEC preference
! Build: gfortran -O3 -fPIC -c routing_score.f90
!        gfortran -shared -o librouting_score.so routing_score.o
! ISO_C_BINDING exports for Rust `src/routing.rs`.

module routing_score
  use, intrinsic :: iso_c_binding
  implicit none
  private
  public :: rs_score_servers, rs_update_sample, rs_pick_best
  public :: rs_init_table, rs_reset_server

  integer, parameter :: MAX_SERVERS = 64
  real(c_double), parameter :: EWMA_ALPHA = 0.25d0
  real(c_double), parameter :: FAIL_PENALTY = 50.0d0   ! ms equivalent
  real(c_double), parameter :: DNSSEC_BONUS = 5.0d0    ! ms equivalent
  real(c_double), parameter :: UNREACH_SCORE = 1.0d12

  type, bind(C) :: server_metrics
     real(c_double) :: ewma_rtt_ms
     real(c_double) :: ewma_fail          ! 0..1
     integer(c_int)  :: samples
     integer(c_int)  :: consecutive_fail
     integer(c_int)  :: dnssec_ok         ! 1/0
     integer(c_int)  :: reachable         ! 1/0
     integer(c_int)  :: family_pref       ! lower = better (v6/v4 policy)
     integer(c_int)  :: scope_pref        ! link/global ordering
  end type server_metrics

contains

  subroutine rs_init_table(n, table) bind(C, name="rs_init_table")
    integer(c_int), intent(in), value :: n
    type(server_metrics), intent(out) :: table(MAX_SERVERS)
    integer :: i, m
    m = min(int(n), MAX_SERVERS)
    do i = 1, MAX_SERVERS
       table(i)%ewma_rtt_ms = 100.0d0
       table(i)%ewma_fail = 0.0d0
       table(i)%samples = 0
       table(i)%consecutive_fail = 0
       table(i)%dnssec_ok = 0
       table(i)%reachable = 1
       table(i)%family_pref = 0
       table(i)%scope_pref = 0
    end do
    if (m < 0) return
  end subroutine rs_init_table

  subroutine rs_reset_server(idx0, table) bind(C, name="rs_reset_server")
    integer(c_int), intent(in), value :: idx0
    type(server_metrics), intent(inout) :: table(MAX_SERVERS)
    integer :: i
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_SERVERS) return
    table(i)%ewma_rtt_ms = 100.0d0
    table(i)%ewma_fail = 0.0d0
    table(i)%samples = 0
    table(i)%consecutive_fail = 0
    table(i)%reachable = 1
  end subroutine rs_reset_server

  ! success=1 rtt_ms used; success=0 counts as failure (rtt ignored)
  subroutine rs_update_sample(idx0, success, rtt_ms, table) &
       bind(C, name="rs_update_sample")
    integer(c_int), intent(in), value :: idx0, success
    real(c_double), intent(in), value :: rtt_ms
    type(server_metrics), intent(inout) :: table(MAX_SERVERS)
    integer :: i
    real(c_double) :: a, r, f
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_SERVERS) return
    a = EWMA_ALPHA
    if (success /= 0) then
       r = max(rtt_ms, 0.0d0)
       if (table(i)%samples == 0) then
          table(i)%ewma_rtt_ms = r
       else
          table(i)%ewma_rtt_ms = a * r + (1.0d0 - a) * table(i)%ewma_rtt_ms
       end if
       f = 0.0d0
       table(i)%consecutive_fail = 0
       table(i)%reachable = 1
    else
       f = 1.0d0
       table(i)%consecutive_fail = table(i)%consecutive_fail + 1
       if (table(i)%consecutive_fail >= 5) table(i)%reachable = 0
    end if
    if (table(i)%samples == 0) then
       table(i)%ewma_fail = f
    else
       table(i)%ewma_fail = a * f + (1.0d0 - a) * table(i)%ewma_fail
    end if
    table(i)%samples = table(i)%samples + 1
  end subroutine rs_update_sample

  pure real(c_double) function score_one(s) result(sc)
    type(server_metrics), intent(in) :: s
    real(c_double) :: pen, bonus, fam, sco
    if (s%reachable == 0) then
       sc = UNREACH_SCORE
       return
    end if
    pen = FAIL_PENALTY * s%ewma_fail * (1.0d0 + 0.25d0 * dble(s%consecutive_fail))
    bonus = 0.0d0
    if (s%dnssec_ok /= 0) bonus = DNSSEC_BONUS
    fam = 0.5d0 * dble(s%family_pref)
    sco = 0.25d0 * dble(s%scope_pref)
    sc = s%ewma_rtt_ms + pen - bonus + fam + sco
  end function score_one

  subroutine rs_score_servers(n, table, out_scores) bind(C, name="rs_score_servers")
    integer(c_int), intent(in), value :: n
    type(server_metrics), intent(in) :: table(MAX_SERVERS)
    real(c_double), intent(out) :: out_scores(MAX_SERVERS)
    integer :: i, m
    m = min(int(n), MAX_SERVERS)
    ! Vector-friendly tight loop — gfortran auto-SIMDs at -O3
    do i = 1, m
       out_scores(i) = score_one(table(i))
    end do
    do i = m + 1, MAX_SERVERS
       out_scores(i) = UNREACH_SCORE
    end do
  end subroutine rs_score_servers

  ! Returns 0-based index of best server, or -1 if none.
  function rs_pick_best(n, table) result(best) bind(C, name="rs_pick_best")
    integer(c_int), intent(in), value :: n
    type(server_metrics), intent(in) :: table(MAX_SERVERS)
    integer(c_int) :: best
    integer :: i, m
    real(c_double) :: sc, best_sc
    best = -1_c_int
    best_sc = UNREACH_SCORE
    m = min(int(n), MAX_SERVERS)
    do i = 1, m
       sc = score_one(table(i))
       if (sc < best_sc) then
          best_sc = sc
          best = int(i - 1, c_int)
       end if
    end do
  end function rs_pick_best

end module routing_score
