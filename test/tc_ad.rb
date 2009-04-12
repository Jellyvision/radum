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
      # You have to remove a container from its directory so that its removed
      # flag is set or the other directory will ignore it.
      @ad2.remove_container @c2_ad2
      @ad1a.add_container @c2_ad2
    end
  end
  
  def test_add_container
    assert_block("Should have added exactly one container") do
      # Containers add themselves to directories on initialization, so this
      # would be an attempt to add a second time. We want to be totally certain,
      # so the add is done a third time anyway. Note that the cn=Users container
      # is added automatically, so the count should be 2.
      @ad1a.add_container @c1_ad1a
      @ad1a.add_container @c1_ad1a
      @ad1a.containers.length == 2
    end
  end
  
  def test_add_container_removed_flag_manually_set
    assert_block("Should have added exactly one container") do
      # Containers add themselves to directories on initialization, so this
      # would be an attempt to add a second time. We want to be totally certain,
      # so the add is done a third time anyway. Note that the cn=Users container
      # is added automatically, so the count shoud be 2.
      @ad1a.add_container @c1_ad1a
      @c1_ad1a.removed = true
      @ad1a.add_container @c1_ad1a
      @ad1a.containers.length == 2
    end
  end
  
  def test_remove_container_ad_removed_flag_set
    assert_block("Should have set removed container ad_removed flag") do
      @ad1a.remove_container @c1_ad1a
      @c1_ad1a.removed == true
    end
  end
end
