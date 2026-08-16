! kalman_upstream.f90
! Einstein-tier upstream selection: 1D Kalman RTT estimator +
! multi-objective ranking (latency, loss, DNSSEC, scope, cost).
!
! gfortran -O3 -fPIC -shared -o libkalman_upstream.so kalman_upstream.f90

module kalman_upstream
  use, intrinsic :: iso_c_binding
  implicit none
  private
  public :: ku_init, ku_observe, ku_predict_rtt, ku_rank, ku_mark_unreachable
  public :: ku_set_weights, ku_snapshot

  integer, parameter :: MAX_U = 128
  real(c_double), parameter :: R_MEAS = 25.0d0      ! measurement noise (ms^2)
  real(c_double), parameter :: Q_PROC_DEFAULT = 4.0d0

  type, bind(C) :: ku_state
     real(c_double) :: x          ! estimated RTT ms
     real(c_double) :: p          ! error covariance
     real(c_double) :: q          ! process noise
     real(c_double) :: loss_ewma  ! 0..1
     real(c_double) :: jitter     ! |innov| ewma
     integer(c_int) :: n
     integer(c_int) :: consec_fail
     integer(c_int) :: reachable
     integer(c_int) :: dnssec
     integer(c_int) :: scope      ! 0 global .. higher = worse
     integer(c_int) :: family     ! 0 preferred
     integer(c_int) :: cost       ! administrative cost
     integer(c_int) :: transport  ! 0 udp 1 tcp 2 tls 3 https
  end type ku_state

  type, bind(C) :: ku_weights
     real(c_double) :: w_rtt
     real(c_double) :: w_loss
     real(c_double) :: w_jitter
     real(c_double) :: w_fail
     real(c_double) :: w_dnssec   ! bonus (subtracted)
     real(c_double) :: w_scope
     real(c_double) :: w_family
     real(c_double) :: w_cost
     real(c_double) :: w_transport
  end type ku_weights

  type(ku_weights), save :: W
  logical, save :: ready = .false.

contains

  subroutine ku_set_weights(ww) bind(C, name="ku_set_weights")
    type(ku_weights), intent(in) :: ww
    W = ww
  end subroutine ku_set_weights

  subroutine default_weights()
    W%w_rtt = 1.0d0
    W%w_loss = 80.0d0
    W%w_jitter = 0.35d0
    W%w_fail = 15.0d0
    W%w_dnssec = 8.0d0
    W%w_scope = 0.4d0
    W%w_family = 0.5d0
    W%w_cost = 1.0d0
    W%w_transport = 2.0d0
  end subroutine default_weights

  subroutine ku_init(n, tbl) bind(C, name="ku_init")
    integer(c_int), intent(in), value :: n
    type(ku_state), intent(out) :: tbl(MAX_U)
    integer :: i, m
    if (.not. ready) then
       call default_weights()
       ready = .true.
    end if
    m = min(int(n), MAX_U)
    do i = 1, MAX_U
       tbl(i)%x = 40.0d0
       tbl(i)%p = 100.0d0
       tbl(i)%q = Q_PROC_DEFAULT
       tbl(i)%loss_ewma = 0.0d0
       tbl(i)%jitter = 5.0d0
       tbl(i)%n = 0
       tbl(i)%consec_fail = 0
       tbl(i)%reachable = 1
       tbl(i)%dnssec = 0
       tbl(i)%scope = 0
       tbl(i)%family = 0
       tbl(i)%cost = 0
       tbl(i)%transport = 0
    end do
    if (m < 0) return
  end subroutine ku_init

  ! Kalman update: success=1 with rtt_ms; success=0 → loss only
  subroutine ku_observe(idx0, success, rtt_ms, tbl) bind(C, name="ku_observe")
    integer(c_int), intent(in), value :: idx0, success
    real(c_double), intent(in), value :: rtt_ms
    type(ku_state), intent(inout) :: tbl(MAX_U)
    integer :: i
    real(c_double) :: x_pred, p_pred, k_gain, innov, z, alpha
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_U) return
    alpha = 0.2d0

    ! predict
    x_pred = tbl(i)%x
    p_pred = tbl(i)%p + tbl(i)%q

    if (success /= 0) then
       z = max(rtt_ms, 0.05d0)
       innov = z - x_pred
       k_gain = p_pred / (p_pred + R_MEAS)
       tbl(i)%x = x_pred + k_gain * innov
       tbl(i)%p = (1.0d0 - k_gain) * p_pred
       tbl(i)%jitter = alpha * abs(innov) + (1.0d0 - alpha) * tbl(i)%jitter
       tbl(i)%loss_ewma = (1.0d0 - alpha) * tbl(i)%loss_ewma
       tbl(i)%consec_fail = 0
       tbl(i)%reachable = 1
       ! adaptive Q: inflate when innov large
       if (abs(innov) > 3.0d0 * sqrt(max(p_pred, 1.0d0))) then
          tbl(i)%q = min(tbl(i)%q * 1.5d0, 100.0d0)
       else
          tbl(i)%q = max(tbl(i)%q * 0.95d0, 0.5d0)
       end if
    else
       tbl(i)%p = p_pred
       tbl(i)%loss_ewma = alpha * 1.0d0 + (1.0d0 - alpha) * tbl(i)%loss_ewma
       tbl(i)%consec_fail = tbl(i)%consec_fail + 1
       if (tbl(i)%consec_fail >= 4) tbl(i)%reachable = 0
       ! slow decay of RTT confidence
       tbl(i)%p = min(tbl(i)%p * 1.2d0, 1.0d4)
    end if
    tbl(i)%n = tbl(i)%n + 1
  end subroutine ku_observe

  function ku_predict_rtt(idx0, tbl) result(rtt) bind(C, name="ku_predict_rtt")
    integer(c_int), intent(in), value :: idx0
    type(ku_state), intent(in) :: tbl(MAX_U)
    real(c_double) :: rtt
    integer :: i
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_U) then
       rtt = 1.0d9
       return
    end if
    rtt = tbl(i)%x
  end function ku_predict_rtt

  pure real(c_double) function score_of(s) result(sc)
    type(ku_state), intent(in) :: s
    real(c_double) :: bonus, pen
    if (s%reachable == 0) then
       sc = 1.0d15
       return
    end if
    bonus = 0.0d0
    if (s%dnssec /= 0) bonus = W%w_dnssec
    pen = W%w_fail * dble(s%consec_fail)
    sc = W%w_rtt * s%x + W%w_loss * s%loss_ewma * 100.0d0 + &
         W%w_jitter * s%jitter + pen + &
         W%w_scope * dble(s%scope) + W%w_family * dble(s%family) + &
         W%w_cost * dble(s%cost) + W%w_transport * dble(s%transport) - bonus
  end function score_of

  ! out_order: 0-based indices best→worst; out_scores parallel
  subroutine ku_rank(n, tbl, out_order, out_scores) bind(C, name="ku_rank")
    integer(c_int), intent(in), value :: n
    type(ku_state), intent(in) :: tbl(MAX_U)
    integer(c_int), intent(out) :: out_order(MAX_U)
    real(c_double), intent(out) :: out_scores(MAX_U)
    integer :: i, j, m, tmp
    real(c_double) :: sc, tsc
    m = min(int(n), MAX_U)
    do i = 1, m
       out_order(i) = int(i - 1, c_int)
       out_scores(i) = score_of(tbl(i))
    end do
    ! insertion sort (m <= 128)
    do i = 2, m
       tmp = out_order(i)
       tsc = out_scores(i)
       j = i - 1
       do while (j >= 1)
          if (out_scores(j) <= tsc) exit
          out_order(j + 1) = out_order(j)
          out_scores(j + 1) = out_scores(j)
          j = j - 1
       end do
       out_order(j + 1) = tmp
       out_scores(j + 1) = tsc
    end do
    do i = m + 1, MAX_U
       out_order(i) = -1
       out_scores(i) = 1.0d15
    end do
  end subroutine ku_rank

  subroutine ku_mark_unreachable(idx0, tbl) bind(C, name="ku_mark_unreachable")
    integer(c_int), intent(in), value :: idx0
    type(ku_state), intent(inout) :: tbl(MAX_U)
    integer :: i
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_U) return
    tbl(i)%reachable = 0
    tbl(i)%consec_fail = max(tbl(i)%consec_fail, 4)
  end subroutine ku_mark_unreachable

  subroutine ku_snapshot(idx0, tbl, x, p, loss, jitter, n, reach) &
       bind(C, name="ku_snapshot")
    integer(c_int), intent(in), value :: idx0
    type(ku_state), intent(in) :: tbl(MAX_U)
    real(c_double), intent(out) :: x, p, loss, jitter
    integer(c_int), intent(out) :: n, reach
    integer :: i
    i = int(idx0) + 1
    if (i < 1 .or. i > MAX_U) then
       x = 0; p = 0; loss = 1; jitter = 0; n = 0; reach = 0
       return
    end if
    x = tbl(i)%x; p = tbl(i)%p; loss = tbl(i)%loss_ewma
    jitter = tbl(i)%jitter; n = tbl(i)%n; reach = tbl(i)%reachable
  end subroutine ku_snapshot

end module kalman_upstream
