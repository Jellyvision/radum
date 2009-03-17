require 'test/unit'
require '../active-directory'

# This tests the Group and UNIXGroup classes.
class TC_Group < Test::Unit::TestCase
  def setup
    c1 = ActiveDirectory::Container.new("ou=People")
    c2 = ActiveDirectory::Container.new("ou=Staff,ou=People")
    ad1 = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1")
    ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @g1a_ad1_c1 = ActiveDirectory::Group.new("staff", ad1, c1)
    @g1b_ad1_c1 = ActiveDirectory::Group.new("staff", ad1, c1)
    @g1c_ad1_c1 = ActiveDirectory::Group.new("Staff", ad1, c1)
    @g1d_ad1_c2 = ActiveDirectory::Group.new("staff", ad1, c2)
    @g1_ad2_c1 = ActiveDirectory::Group.new("staff", ad2, c1)
    @ug1_ad1_c1 = ActiveDirectory::UNIXGroup.new("class", ad1, c1, 1001)
  end
  
  def test_equal
    assert(@g1a_ad1_c1 == @g1b_ad1_c1, "Should be equal")
  end
  
  def test_equal_name_case
    assert(@g1a_ad1_c1 == @g1c_ad1_c1, "Should be equal")
  end
  
  def test_equal_container
    assert(@g1a_ad1_c1 == @g1d_ad1_c2, "Should be equal")
  end
  
  def test_not_equal_ad
    assert(@g1a_ad1_c1 != @g1_ad2_c1, "Should not be equal")
  end
  
  def test_not_equal_group_unix_group
    assert(@g1a_ad1_c1 != @ug1_ad1_c1, "Should not be equal")
  end
end
