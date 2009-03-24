require 'test/unit'
require '../active-directory'

# This tests the Container class.
class TC_Ad < Test::Unit::TestCase
  def setup
    @ad1a = ActiveDirectory::AD.new("dc=vmware,dc=local", "test1a")
    @ad1b = ActiveDirectory::AD.new("dc=vmware, dc=local", "test1b")
    @ad1c = ActiveDirectory::AD.new("DC=VMWARE,DC=LOCAL", "test1c")
    @ad2 = ActiveDirectory::AD.new("dc=vmware,dc=com", "test2")
    @c1_ad1a = ActiveDirectory::Container.new("ou=People", @ad1a)
    @c2_ad2 = ActiveDirectory::Container.new("ou=Staff,ou=People", @ad2)
    @g1_ad1a_c1_ad1a = ActiveDirectory::Group.new("staff", @ad1a, @c1_ad1a)
    @u1a_ad1a_c1_ad1a = ActiveDirectory::User.new("user", @ad1a, @c1_ad1a)
  end
  
  def test_equal
    assert(@ad1a == @ad1a, "Should be equal")
  end
  
  def test_equal_spaces
    assert(@ad1a == @ad1b, "Should be equal with spaces")
  end
  
  def test_equal_case
    assert(@ad1a == @ad1c, "Should be equal with different case names")
  end
  
  def test_not_equal
    assert(@ad1a != @ad2, "Should not be equal")
  end
  
  def test_add_container_different_directory_exception
    assert_raise RuntimeError do
      @ad1a.add_container @c2_ad2
    end
  end
  
  def test_add_container
    assert_block("Should have added exactly one container") do
      @ad1a.add_container @c1_ad1a
      @ad1a.add_container @c1_ad1a
      @ad1a.containers.length == 1
    end
  end
  
  def test_add_user
    assert_block("Should have added exactly one user") do
      @ad1a.add_container @c1_ad1a
      @ad1a.add_user @u1a_ad1a_c1_ad1a
      @ad1a.add_user @u1a_ad1a_c1_ad1a
      @ad1a.users.length == 1
    end
  end
  
  def test_add_user_without_container_exception
    assert_raise RuntimeError do
      @ad1a.add_user @u1a_ad1a_c1_ad1a
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly one group") do
      @ad1a.add_container @c1_ad1a
      @ad1a.add_group @g1_ad1a_c1_ad1a
      @ad1a.add_group @g1_ad1a_c1_ad1a
      @ad1a.groups.length == 1
    end
  end
  
  def test_add_group_without_container_exception
    assert_raise RuntimeError do
      @ad1a.add_group @g1_ad1a_c1_ad1a
    end
  end
end
