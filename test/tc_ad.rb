require 'test/unit'
require 'radum'

# This tests the AD class.
class TC_Ad < Test::Unit::TestCase
  def setup
    @ad1a = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1a"
    @ad1b = RADUM::AD.new :root => "dc=vmware, dc=local", :password => "test1b"
    @ad1c = RADUM::AD.new :root => "DC=VMWARE,DC=LOCAL", :password => "test1c"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1a = RADUM::Container.new :name => "ou=People", :directory => @ad1a
    @c2_ad2 = RADUM::Container.new :name => "ou=Staff,ou=People",
                                   :directory => @ad2
  end
  
  def test_equal
    assert(@ad1a == @ad1a, "Should be equal")
  end
  
  def test_equal_domain
    assert(@ad1a.domain == @ad1c.domain, "Should be equal domain attribute")
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
      # Containers add themselves to directories on initialization, so this
      # would be an attempt to add a second time. We want to be totally certain,
      # so the add is done a third time anyway. Note that the cn=Users container
      # is added automatically, so the count should be 2.
      @ad1a.add_container @c1_ad1a
      @ad1a.add_container @c1_ad1a
      @ad1a.containers.length == 2
    end
  end
  
  def test_remove_container_ad_removed_flag_set
    assert_block("Should have set removed container ad_removed flag") do
      @ad1a.remove_container @c1_ad1a
      @c1_ad1a.removed? == true
    end
  end
end
