require 'test/unit'
require '../active-directory'

# This tests the Container class.
class TC_Container < Test::Unit::TestCase
  def setup
    @ad1 = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1")
    @ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @c1a_ad1 = ActiveDirectory::Container.new("ou=People", @ad1)
    @c1b_ad1 = ActiveDirectory::Container.new("ou=People", @ad1)
    @c1c_ad1 = ActiveDirectory::Container.new("ou=people", @ad1)
    @c2a_ad1 = ActiveDirectory::Container.new("ou=Staff,ou=People", @ad1)
    @c2b_ad1 = ActiveDirectory::Container.new("ou=Staff, ou=People", @ad1)
    @c3_ad1 = ActiveDirectory::Container.new("cn=Users", @ad1)
    @c4_ad2 = ActiveDirectory::Container.new("cn=Users", @ad2)
    @g1_ad1_c1a_ad1 = ActiveDirectory::Group.new("staff", @ad1, @c1a_ad1)
    @g2_ad2_c4_ad2 = ActiveDirectory::Group.new("enable", @ad2, @c4_ad2)
    @u1_ad1_c1a_ad1 = ActiveDirectory::User.new("user", @ad1, @c1a_ad1)
    @u2_ad2_c4_ad2 = ActiveDirectory::User.new("user", @ad2, @c4_ad2)
  end
  
  def test_no_spaces
    assert(@c2b_ad1.name.split(/\s+/).length == 1,
           "Should be no spaces in name")
  end
  
  def test_equal
    assert(@c1a_ad1 == @c1b_ad1, "Should be equal")
  end
  
  def test_equal_case_insensitive
    assert(@c1a_ad1 == @c1c_ad1, "Should be equal with difference case")
  end
  
  def test_equal_spaces
    assert(@c2a_ad1 == @c2b_ad1, "Should be equal with whitespace difference")
  end
  
  def test_not_equal
    assert(@c1a_ad1 != @c3_ad1, "Should not be equal")
  end
  
  def test_not_equal_ad
    assert(@c3_ad1 != @c4_ad2, "Should not be equal")
  end
  
  def test_add_user
    assert_block("Should have added exactly one user") do
      @c1a_ad1.add_user @u1_ad1_c1a_ad1
      @c1a_ad1.add_user @u1_ad1_c1a_ad1
      @c1a_ad1.users.length == 1
    end
  end
  
  def test_add_user_exception
    assert_raise RuntimeError do
      @c1a_ad1.add_user @u2_ad2_c4_ad2
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly one group") do
      @c1a_ad1.add_group @g1_ad1_c1a_ad1
      @c1a_ad1.add_group @g1_ad1_c1a_ad1
      @c1a_ad1.groups.length == 1
    end
  end
  
  def test_add_group_exception
    assert_raise RuntimeError do
      @c1a_ad1.add_group @g2_ad2_c4_ad2
    end
  end
end
