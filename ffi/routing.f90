! SPDX-License-Identifier: LGPL-2.1-or-later
module resolved_routing
  use, intrinsic :: iso_c_binding, only: c_char, c_int, c_int64_t, c_size_t
  implicit none
  private
  public :: resolved_route_score
contains
  pure integer(c_int) function ascii_lower(value) result(lowered)
    integer(c_int), intent(in) :: value
    if (value >= iachar('A') .and. value <= iachar('Z')) then
      lowered = value + (iachar('a') - iachar('A'))
    else
      lowered = value
    end if
  end function ascii_lower

  pure logical function equal_ascii(left, right) result(equal)
    character(kind=c_char), intent(in) :: left
    character(kind=c_char), intent(in) :: right
    equal = ascii_lower(iachar(left)) == ascii_lower(iachar(right))
  end function equal_ascii

  pure integer(c_int) function label_count(domain, domain_len) result(count)
    character(kind=c_char), intent(in) :: domain(*)
    integer(c_size_t), value, intent(in) :: domain_len
    integer(c_size_t) :: index

    if (domain_len == 0_c_size_t) then
      count = 0_c_int
      return
    end if

    count = 1_c_int
    do index = 1_c_size_t, domain_len
      if (domain(index) == '.') count = count + 1_c_int
    end do
  end function label_count

  pure logical function suffix_matches(name, name_len, domain, domain_len) result(matches)
    character(kind=c_char), intent(in) :: name(*)
    character(kind=c_char), intent(in) :: domain(*)
    integer(c_size_t), value, intent(in) :: name_len
    integer(c_size_t), value, intent(in) :: domain_len
    integer(c_size_t) :: name_start
    integer(c_size_t) :: index

    if (domain_len == 0_c_size_t) then
      matches = .true.
      return
    end if
    if (domain_len > name_len) then
      matches = .false.
      return
    end if

    name_start = name_len - domain_len + 1_c_size_t
    if (name_start > 1_c_size_t) then
      if (name(name_start - 1_c_size_t) /= '.') then
        matches = .false.
        return
      end if
    end if

    do index = 1_c_size_t, domain_len
      if (.not. equal_ascii(name(name_start + index - 1_c_size_t), domain(index))) then
        matches = .false.
        return
      end if
    end do
    matches = .true.
  end function suffix_matches

  integer(c_int64_t) function resolved_route_score( &
      name, name_len, domain, domain_len, route_only, default_route, ifindex) &
      bind(C, name='resolved_route_score') result(score)
    character(kind=c_char), intent(in) :: name(*)
    character(kind=c_char), intent(in) :: domain(*)
    integer(c_size_t), value, intent(in) :: name_len
    integer(c_size_t), value, intent(in) :: domain_len
    integer(c_int), value, intent(in) :: route_only
    integer(c_int), value, intent(in) :: default_route
    integer(c_int), value, intent(in) :: ifindex
    integer(c_int64_t) :: labels
    integer(c_int64_t) :: tie_break

    if (.not. suffix_matches(name, name_len, domain, domain_len)) then
      score = -1_c_int64_t
      return
    end if

    labels = int(label_count(domain, domain_len), c_int64_t)
    tie_break = int(max(0_c_int, min(ifindex, 65535_c_int)), c_int64_t)
    score = labels * 1000000_c_int64_t
    if (route_only /= 0_c_int) score = score + 100000_c_int64_t
    if (default_route /= 0_c_int) score = score + 10000_c_int64_t
    score = score + tie_break
  end function resolved_route_score
end module resolved_routing
