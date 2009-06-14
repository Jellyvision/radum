require 'test/unit'
require '../lib/radum'

# This tests the Group and UNIXGroup classes.
class TC_Group < Test::Unit::TestCase
  def setup
    @type = RADUM::GROUP_GLOBAL_SECURITY
    @ad1 = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1 = RADUM::Container.new :name => "ou=People", :directory => @ad1
    @c2_ad1 = RADUM::Container.new :name => "ou=Staff,ou=People",
                                   :directory => @ad1
    @c3_ad2 = RADUM::Container.new :name => "ou=People", :directory => @ad2
    @g1_c1_ad1 = RADUM::Group.new("staff", @c1_ad1, @type, 1722)
    @g2_c3_ad2 = RADUM::Group.new("staff", @c3_ad2, @type, 1722)
    @g4_c1_ad1 = RADUM::Group.new("primary", @c1_ad1)
    @g5_c3_ad2 = RADUM::Group.new("priamry", @c3_ad2)
    @ug1_c1_ad1 = RADUM::UNIXGroup.new("class", @c1_ad1, 1001)
    @u1_c1_ad1 = RADUM::User.new("user1", @c1_ad1, @g4_c1_ad1)
    @u2_c3_ad2 = RADUM::User.new("user2", @c3_ad2, @g5_c3_ad2)
    @uu1_c1_ad1 = RADUM::UNIXUser.new("user3", @c1_ad1, @g4_c1_ad1, 1000,
                                      @ug1_c1_ad1, "/bin/bash", "/home/user")
  end
  
  def test_removed_flag_false
    assert_block("Removed flags should be false.") do
      @g1_c1_ad1.removed == false && @ug1_c1_ad1.removed == false
    end
  end
  
  def test_duplicate_rid_exception
    assert_raise RuntimeError do
      RADUM::Group.new("test", @c1_ad1, @type, 1722)
    end
  end
  
  def test_duplicate_gid_exception
    assert_raise RuntimeError do
      RADUM::UNIXGroup.new("class", @c1_ad1, 1001)
    end
  end
  
  def test_equal_exception
    assert_raise RuntimeError do
      RADUM::Group.new("staff", @c1_ad1)
    end
  end
  
  def test_equal_name_case_exception
    assert_raise RuntimeError do
      RADUM::Group.new("Staff", @c1_ad1)
    end
  end
  
  def test_equal_container_difference_exception
    assert_raise RuntimeError do
      RADUM::Group.new("staff", @c2_ad1)
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
  
  def test_add_user_primary_group_exception
    assert_raise RuntimeError do
      @g4_c1_ad1.add_user @u1_c1_ad1
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
  
  def test_remove_user_main_unix_group_exception
    assert_raise RuntimeError do
      @ug1_c1_ad1.remove_user @uu1_c1_ad1
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
