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
    @g1a_ad1_c1_ad1 = ActiveDirectory::Group.new("staff", @ad1, @c1_ad1)
    @g1b_ad1_c1_ad1 = ActiveDirectory::Group.new("staff", @ad1, @c1_ad1)
    @g1c_ad1_c1_ad1 = ActiveDirectory::Group.new("Staff", @ad1, @c1_ad1)
    @g1d_ad1_c2_ad1 = ActiveDirectory::Group.new("staff", @ad1, @c2_ad1)
    @g2_ad2_c3_ad2 = ActiveDirectory::Group.new("staff", @ad2, @c3_ad2)
    @ug1_ad1_c1_ad1 = ActiveDirectory::UNIXGroup.new("class", @ad1, @c1_ad1,
                                                     1001)
  end
  
  def test_different_container_directory_exception
    assert_raise RuntimeError do
      ActiveDirectory::Group.new("enable", @ad1, @c3_ad2)
    end
  end
  
  def test_equal
    assert(@g1a_ad1_c1_ad1 == @g1b_ad1_c1_ad1, "Should be equal")
  end
  
  def test_equal_name_case
    assert(@g1a_ad1_c1_ad1 == @g1c_ad1_c1_ad1, "Should be equal")
  end
  
  def test_equal_container_name_difference
    assert(@g1a_ad1_c1_ad1 == @g1d_ad1_c2_ad1, "Should be equal")
  end
  
  def test_not_equal_ad
    assert(@g1a_ad1_c1_ad1 != @g2_ad2_c3_ad2, "Should not be equal")
  end
  
  def test_not_equal_group_unix_group
    assert(@g1a_ad1_c1_ad1 != @ug1_ad1_c1_ad1, "Should not be equal")
  end
end
