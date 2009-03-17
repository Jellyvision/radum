require 'test/unit'
require '../active-directory'

# This tests the User class.
class TC_User < Test::Unit::TestCase
  def setup
    c1 = ActiveDirectory::Container.new("ou=People")
    c2 = ActiveDirectory::Container.new("ou=Staff,ou=People")
    ad1 = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1")
    ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @g1_ad1_c1 = ActiveDirectory::Group.new("staff", ad1, c1)
    @g2_ad1_c2 = ActiveDirectory::Group.new("enable", ad1, c2)
    @g1_ad2_c1 = ActiveDirectory::Group.new("staff", ad2, c1)
    @ug1_ad1_c1 = ActiveDirectory::UNIXGroup.new("class", ad1, c1, 1001)
    @ug1_ad2_c1 = ActiveDirectory::UNIXGroup.new("class", ad2, c1, 1001)
    @u1a_ad1_c1 = ActiveDirectory::User.new("user", ad1, c1)
    @u1b_ad1_c1 = ActiveDirectory::User.new("user", ad1, c1)
    @u1c_ad1_c2 = ActiveDirectory::User.new("user", ad1, c2)
    @u2_ad2_c1 = ActiveDirectory::User.new("user", ad2, c1)
  end
  
  def test_equal
    assert(@u1a_ad1_c1 == @u1b_ad1_c1, "Should be equal")
  end
  
  def test_equal_container
    assert(@u1a_ad1_c1 == @u1c_ad1_c2, "Should be equal")
  end
  
  def test_not_equal_ad
    assert(@u1a_ad1_c1 != @u2_ad2_c1, "Should not be equal")
  end
  
  def test_equal_common_name_change
    @u1a_ad1_c1.common_name = "Test User"
    assert(@u1a_ad1_c1 == @u1b_ad1_c1,
           "Should be equal with common_name change")
  end
  
  def test_add_unix_group_no_exception
    assert_nothing_raised do
      @u1a_ad1_c1.add_group @ug1_ad1_c1
    end
  end
  
  def test_add_unix_group_different_directory_exception
    assert_raise RuntimeError do
      @u1a_ad1_c1.add_group(@ug1_ad2_c1)
    end
  end
  
  def test_group_add_different_directory_exception
    assert_raise RuntimeError do
      @u1a_ad1_c1.add_group(@g1_ad2_c1)
    end
  end
  
  def test_add_group_no_exception
    assert_nothing_raised do
      @u1a_ad1_c1.add_group @g1_ad1_c1
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly two groups") do
      @u1a_ad1_c1.add_group(@g1_ad1_c1)
      @u1a_ad1_c1.add_group(@g2_ad1_c2)
      @u1a_ad1_c1.add_group(@g2_ad1_c2)
      @u1a_ad1_c1.groups.length == 2 &&
      @u1a_ad1_c1.groups.find { |group| group == @g1_ad1_c1 } &&
      @u1a_ad1_c1.groups.find { |group| group = @g2_ad1_c2 }
    end
  end
end
