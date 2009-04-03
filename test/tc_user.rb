require 'test/unit'
require '../active-directory'

# This tests the User class.
class TC_User < Test::Unit::TestCase
  def setup
    @ad1 = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1")
    @ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @c1_ad1 = ActiveDirectory::Container.new("ou=People", @ad1)
    @c2_ad1 = ActiveDirectory::Container.new("ou=Staff,ou=People", @ad1)
    @c3_ad2 = ActiveDirectory::Container.new("ou=People", @ad2)
    @g1_c1_ad1 = ActiveDirectory::Group.new("staff", @c1_ad1)
    @g2_c2_ad1 = ActiveDirectory::Group.new("enable", @c2_ad1)
    @g3_c3_ad2 = ActiveDirectory::Group.new("staff", @c3_ad2)
    @ug1_c1_ad1 = ActiveDirectory::UNIXGroup.new("class", @c1_ad1, 1001)
    @ug2_c3_ad2 = ActiveDirectory::UNIXGroup.new("class", @c3_ad2, 1001)
    @u1_c1_ad1 = ActiveDirectory::User.new("user", @c1_ad1)
    @u2_c3_ad2 = ActiveDirectory::User.new("user", @c3_ad2)
  end
  
  def test_removed_flag_false
    assert(@u1_c1_ad1.removed == false, "Removed flag should be false")
  end
  
  def test_equal_exception
    assert_raise RuntimeError do
      ActiveDirectory::User.new("user", @c1_ad1)
    end
  end
  
  def test_equal_container_difference_exception
    assert_raise RuntimeError do
      ActiveDirectory::User.new("user", @c2_ad1)
    end
  end
  
  def test_equal_name_case_exception
    assert_raise RuntimeError do
      ActiveDirectory::User.new("User", @c1_ad1)
    end
  end
  
  def test_not_equal_ad
    assert(@u1_c1_ad1 != @u2_c3_ad2, "Should not be equal")
  end
  
  def test_add_unix_group_no_exception
    assert_nothing_raised do
      @u1_c1_ad1.add_group @ug1_c1_ad1
    end
  end
  
  def test_add_unix_group_different_directory_exception
    assert_raise RuntimeError do
      @u1_c1_ad1.add_group @ug2_c3_ad2
    end
  end
  
  def test_group_add_different_directory_exception
    assert_raise RuntimeError do
      @u1_c1_ad1.add_group @g3_c3_ad2
    end
  end
  
  def test_add_group_no_exception
    assert_nothing_raised do
      @u1_c1_ad1.add_group @g1_c1_ad1
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly two groups") do
      @u1_c1_ad1.add_group @g1_c1_ad1
      @u1_c1_ad1.add_group @g2_c2_ad1
      @u1_c1_ad1.add_group @g2_c2_ad1
      @u1_c1_ad1.groups.length == 2 &&
      @u1_c1_ad1.groups.find { |group| group == @g1_c1_ad1 } &&
      @u1_c1_ad1.groups.find { |group| group == @g2_c2_ad1 }
    end
  end
  
  def test_user_added_to_container
    assert_block("User should have been automatically added to container") do
      @c1_ad1.users.find do |user|
        user == @u1_c1_ad1
      end
    end
  end
  
  def test_add_group_user_added_to_group
    assert_block("Group should have user when added to user") do
      @u1_c1_ad1.add_group @g1_c1_ad1
      @g1_c1_ad1.users.find do |user|
        user == @u1_c1_ad1
      end
    end
  end
  
  def test_remove_group_user_removed_from_group
    assert_block("Group should have removed user when removed from user") do
      @u1_c1_ad1.add_group @g1_c1_ad1
      @u1_c1_ad1.remove_group @g1_c1_ad1
      ! @g1_c1_ad1.users.find do |user|
        user == @u1_c1_ad1
      end
    end
  end
  
  def test_member_of
    assert_block("User should be member of the single group") do
      @u1_c1_ad1.add_group @g1_c1_ad1
      (@u1_c1_ad1.member_of? @g1_c1_ad1) &&
      ! (@u1_c1_ad1.member_of? @g2_c2_ad1)
    end
  end
end
