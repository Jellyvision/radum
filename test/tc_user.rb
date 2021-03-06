require 'test/unit'
require 'radum'

# This tests the User class.
class TC_User < Test::Unit::TestCase
  def setup
    @type = RADUM::GROUP_DOMAIN_LOCAL_DISTRIBUTION
    @ad1 = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1 = RADUM::Container.new :name => "ou=People", :directory => @ad1
    @c2_ad1 = RADUM::Container.new :name => "ou=Staff,ou=People",
                                   :directory => @ad1
    @c3_ad2 = RADUM::Container.new :name => "ou=People", :directory => @ad2
    @g1_c1_ad1 = RADUM::Group.new :name => "staff", :container => @c1_ad1
    @g2_c2_ad1 = RADUM::Group.new :name => "enable", :container => @c2_ad1
    @g3_c3_ad2 = RADUM::Group.new :name => "staff", :container => @c3_ad2
    @g4_c1_ad1 = RADUM::Group.new :name => "primary", :container => @c1_ad1
    @g5_c3_ad2 = RADUM::Group.new :name => "primary", :container => @c3_ad2
    @ug1_c1_ad1 = RADUM::UNIXGroup.new :name => "class", :container => @c1_ad1,
                                       :gid => 1001
    @ug2_c3_ad2 = RADUM::UNIXGroup.new :name => "class", :container => @c3_ad2,
                                       :gid => 1001
    @u1_c1_ad1 = RADUM::User.new :username => "user", :container => @c1_ad1,
                                 :primary_group => @g4_c1_ad1,
                                 :disabled => false, :rid => 1834
    @u2_c3_ad2 = RADUM::User.new :username => "user", :container => @c3_ad2,
                                 :primary_group => @g5_c3_ad2,
                                 :disabled => false, :rid => 1834
  end
  
  def test_removed_flag_false
    assert(@u1_c1_ad1.removed? == false, "Removed flag should be false")
  end
  
  def test_duplicate_rid_exception
    assert_raise RuntimeError do
      RADUM::User.new :username => "test", :container => @c1_ad1,
                      :primary_group => @g4_c1_ad1, :disabled => false,
                      :rid => 1834
    end
  end
  
  def test_primary_group_type_exception
    assert_raise RuntimeError do
      @u1_c1_ad1.primary_group = RADUM::Group.new :name => "broken",
                                                  :container => @c1_ad1,
                                                  :type => @type
    end
  end
  
  def test_removed_primary_group_exception
    assert_raise RuntimeError do
      @g1_c1_ad1.set_removed
      @u1_c1_ad1.primary_group = @g1_c1_ad1
    end
  end
  
  def test_equal_exception
    assert_raise RuntimeError do
      RADUM::User.new :username => "user", :container => @c1_ad1,
                      :primary_group => @g4_c1_ad1
    end
  end
  
  def test_equal_container_difference_exception
    assert_raise RuntimeError do
      RADUM::User.new :username => "user", :container => @c2_ad1,
                      :primary_group => @g4_c1_ad1
    end
  end
  
  def test_equal_name_case_exception
    assert_raise RuntimeError do
      RADUM::User.new :username => "User", :container => @c1_ad1,
                      :primary_group => @g4_c1_ad1
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
  
  def test_add_primary_group_exception
    assert_raise RuntimeError do
      @u1_c1_ad1.add_group @g4_c1_ad1
    end
  end
  
  def test_modify_distiguished_name_loaded_exception
    assert_raise RuntimeError do
      @u1_c1_ad1.set_loaded
      @u1_c1_ad1.distinguished_name = "cn=error,ou=crazy,dc=fool,dc=com"
    end
  end
  
  def test_change_primary_group_add_old_group
    assert_block("Should have added user to old primary group on change") do
      # The primary group is currently @g4_c1_ad1. Changing it below should
      # automatically add the user to the @g4_c1_ad1 group (which the user is
      # not a member of currently).
      @u1_c1_ad1.primary_group = @g1_c1_ad1
      @u1_c1_ad1.groups.find { |group| group == @g4_c1_ad1 }
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
