require 'test/unit'
require '../active-directory'

# This tests the Group and UNIXGroup classes.
class TC_Group < Test::Unit::TestCase
  def setup
    @ad1 = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1")
    @ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @c1_ad1 = ActiveDirectory::Container.new("ou=People", @ad1)
    @c2_ad1 = ActiveDirectory::Container.new("ou=Staff,ou=People", @ad1)
    @c3_ad2 = ActiveDirectory::Container.new("ou=People", @ad2)
    @g1_c1_ad1 = ActiveDirectory::Group.new("staff", @c1_ad1, 1722)
    @g2_c3_ad2 = ActiveDirectory::Group.new("staff", @c3_ad2, 1722)
    @ug1_c1_ad1 = ActiveDirectory::UNIXGroup.new("class", @c1_ad1, 1001)
    @u1_c1_ad1 = ActiveDirectory::User.new("user1", @c1_ad1)
    @u2_c3_ad2 = ActiveDirectory::User.new("user2", @c3_ad2)
    @uu1_c1_ad1 = ActiveDirectory::UNIXUser.new("user3", @c1_ad1, 1000,
                                                @ug1_c1_ad1, "/bin/bash",
                                                "/home/user")
  end
  
  def test_removed_flag_false
    assert_block("Removed flags should be false.") do
      @g1_c1_ad1.removed == false && @ug1_c1_ad1.removed == false
    end
  end
  
  def test_duplicate_rid_exception
    assert_raise RuntimeError do
      ActiveDirectory::Group.new("test", @c1_ad1, 1722)
    end
  end
  
  def test_duplicate_gid_exception
    assert_raise RuntimeError do
      ActiveDirectory::UNIXGroup.new("class", @c1_ad1, 1001)
    end
  end
  
  def test_equal_exception
    assert_raise RuntimeError do
      ActiveDirectory::Group.new("staff", @c1_ad1)
    end
  end
  
  def test_equal_name_case_exception
    assert_raise RuntimeError do
      ActiveDirectory::Group.new("Staff", @c1_ad1)
    end
  end
  
  def test_equal_container_difference_exception
    assert_raise RuntimeError do
      ActiveDirectory::Group.new("staff", @c2_ad1)
    end
  end
  
  def test_not_equal_ad
    assert(@g1_c1_ad1 != @g2_c3_ad2, "Should not be equal")
  end
  
  def test_not_equal_group_unix_group
    assert(@g1_c1_ad1 != @ug1_c1_ad1, "Should not be equal")
  end
  
  def test_add_user
    assert_block("Should have added exactly one user") do
      @g1_c1_ad1.add_user @u1_c1_ad1
      @g1_c1_ad1.add_user @u1_c1_ad1
      @g1_c1_ad1.users.length == 1
    end
  end
  
  def test_add_user_different_directory_exception
    assert_raise RuntimeError do
      @g1_c1_ad1.add_user @u2_c3_ad2
    end
  end
  
  def test_add_user_main_group_exception
    assert_raise RuntimeError do
      @ug1_c1_ad1.add_user @uu1_c1_ad1
    end
  end
  
  def test_group_added_to_container
    assert_block("Group should have been automatically added to container") do
      @c1_ad1.groups.find do |group|
        group == @g1_c1_ad1
      end
    end
  end
  
  def test_add_user_group_added_to_user
    assert_block("User should have group when added to group") do
      @g1_c1_ad1.add_user @u1_c1_ad1
      @u1_c1_ad1.groups.find do |group|
        group == @g1_c1_ad1
      end
    end
  end
  
  def test_remove_user_group_removed_from_user
    assert_block("User should have removed group when removed from group") do
      @g1_c1_ad1.add_user @u1_c1_ad1
      @g1_c1_ad1.remove_user @u1_c1_ad1
      ! @u1_c1_ad1.groups.find do |group|
        group == @g1_c1_ad1
      end
    end
  end
  
  def test_add_group_self_exception
    assert_raise RuntimeError do
      @g1_c1_ad1.add_group @g1_c1_ad1
    end
  end
  
  def test_add_group_other_directory_exception
    assert_raise RuntimeError do
      @g1_c1_ad1.add_group @g2_c3_ad2
    end
  end
  
  def test_add_group
    assert_block("Group should have added another group") do
      @g1_c1_ad1.add_group @ug1_c1_ad1
      @g1_c1_ad1.groups.find do |group|
        group == @ug1_c1_ad1
      end
    end
  end
  
  def test_remove_group
    assert_block("Group should have been removed") do
      @g1_c1_ad1.add_group @ug1_c1_ad1
      @g1_c1_ad1.remove_group @ug1_c1_ad1
      ! @g1_c1_ad1.groups.find do |group|
        group == @ug1_c1_ad1
      end
    end
  end
end
