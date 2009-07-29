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
    # These objects are to test AD#remove_container and AD#destroy_container.
    @rm_cn1 = RADUM::Container.new :name => "ou=rm", :directory => @ad1a
    @rm_cn2 = RADUM::Container.new :name => "ou=no", :directory => @ad1a
    @rm_wg1 = RADUM::Group.new :name => "wg1", :container => @rm_cn1
    @rm_wg2 = RADUM::Group.new :name => "wg2", :container => @rm_cn2
    @rm_wg2.add_group @rm_wg1
    @rm_wg3 = RADUM::Group.new :name => "wg3", :container => @rm_cn2
    @rm_ug1 = RADUM::UNIXGroup.new :name => "ug1", :container => @rm_cn1,
                                   :gid => 1000
    @rm_ug2 = RADUM::UNIXGroup.new :name => "ug2", :container => @rm_cn2,
                                   :gid => 1001
    @rm_ug3 = RADUM::UNIXGroup.new :name => "ug3", :container => @rm_cn2,
                                   :gid => 1002
    @rm_wu1 = RADUM::User.new :username => "wu1", :container => @rm_cn1,
                              :primary_group => @rm_wg2
    @rm_wu1.add_group @rm_wg1
    @rm_wu1.add_group @rm_wg3
    @rm_wu2 = RADUM::User.new :username => "wu2", :container => @rm_cn2,
                              :primary_group => @rm_wg2
    @rm_wu2.add_group @rm_wg1
    @rm_wu2.add_group @rm_wg3
    @rm_uu1 = RADUM::UNIXUser.new :username => "uu1", :container => @rm_cn1,
                                  :primary_group => @rm_ug3, :uid => 1000,
                                  :unix_main_group => @rm_ug2,
                                  :shell => '/bin/bash',
                                  :home_directory => '/home/uu1'
    @rm_uu2 = RADUM::UNIXUser.new :username => "uu2", :container => @rm_cn2,
                                  :primary_group => @rm_wg2, :uid => 1001,
                                  :unix_main_group => @rm_ug2,
                                  :shell => '/bin/bash',
                                  :home_directory => '/home/uu2'
    @rm_uu2.add_group @rm_wg1
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
      # is added automatically and we did add a second and third one in testing
      # initialization, so the count should be 4.
      @ad1a.add_container @c1_ad1a
      @ad1a.add_container @c1_ad1a
      @ad1a.containers.length == 4
    end
  end
  
  def test_remove_container_ad_removed_flag_set
    assert_block("Should have set removed container ad_removed flag") do
      @ad1a.remove_container @c1_ad1a
      @c1_ad1a.removed? == true
    end
  end
  
  def test_remove_container_false
    # We don't want to see the actual warning messages.
    RADUM::logger.default_level = RADUM::LOG_NONE
    assert(@ad1a.remove_container(@rm_cn2) == false,
           "Should not have removed container")
  end
  
  def test_remove_container_effects
    rm_cn1_users = @rm_cn1.users.clone
    rm_cn1_groups = @rm_cn1.groups.clone
    assert(@ad1a.remove_container(@rm_cn1) == true,
           "Should have removed container")
    
    @rm_cn1.removed_users.each do |user|
      assert(rm_cn1_users.include?(user) == true,
             "User should be in removed_users array for container")
    end
    
    assert(@rm_cn1.users.length == 0, "Container should have no users")
    
    @rm_cn1.removed_groups.each do |group|
      assert(rm_cn1_groups.include?(group) == true,
             "Group should be in removed_groups array for container")
    end
    
    assert(@rm_cn1.groups.length == 0, "Container should have no groups")
    
    @ad1a.users.each do |user|
      assert(rm_cn1_users.include?(user) == false,
             "User should not be in users array for container")
      assert(@rm_cn1.removed_users.include?(user) == false,
             "User should not be in removed_users array for container")
      
      # Make sure each user sees the removed groups correctly.
      rm_cn1_groups.each do |group|
        assert(user.groups.include?(group) == false,
               "User should not have group in groups array")
      end
    end
    
    @ad1a.groups.each do |group|
      assert(rm_cn1_groups.include?(group) == false,
             "Group should not be in groups array for container")
      assert(@rm_cn1.removed_groups.include?(group) == false,
             "Group should not be in removed_groups array for container")
      
      # Make sure each group sees the removed users correctly.
      rm_cn1_users.each do |user|
        assert(group.users.include?(user) == false,
               "Group should not have user in users array")
      end
      
      # Make sure each group sees the removed groups correctly.
      rm_cn1_groups.each do |group|
        assert(group.groups.include?(group) == false,
               "Group should not have group in groups array")
      end
    end
    
    # Manually check @rm_cn2 objects to make sure they see all removed objects
    # in their removed_groups and removed_users arrays.
    assert(@rm_wg2.removed_groups.include?(@rm_wg1) == true,
           "wg1 should be in wg2's removed_groups array")
    assert(@rm_ug2.removed_users.include?(@rm_uu1) == true,
           "uu1 should be in ug2's removed_users array")
    assert(@rm_wg3.removed_users.include?(@rm_wu1) == true,
           "wu1 should be in wg3's removed_users array")
    assert(@rm_wu2.removed_groups.include?(@rm_wg1) == true,
           "wg1 should be in wu2's removed_groups array")
    assert(@rm_uu2.removed_groups.include?(@rm_wg1) == true,
           "wg1 should be in uu2's removed_groups array")
  end
  
  def test_destroy_container_false
    # We don't want to see the actual warning messages.
    RADUM::logger.default_level = RADUM::LOG_NONE
    assert(@ad1a.destroy_container(@rm_cn2) == false,
           "Should not have destroyed container")
  end
  
  def test_destroy_container_effects
    rm_cn1_users = @rm_cn1.users.clone
    rm_cn1_groups = @rm_cn1.groups.clone
    assert(@ad1a.destroy_container(@rm_cn1) == true,
           "Should have removed container")
    
    assert(@rm_cn1.users.length == 0, "Container should have no users")
    assert(@rm_cn1.removed_users.length == 0,
           "Container should have no removed users")
    assert(@rm_cn1.groups.length == 0, "Container should have no groups")
    assert(@rm_cn1.removed_groups.length == 0,
           "Container should have no removed groups")
    
    @ad1a.users.each do |user|
      assert(rm_cn1_users.include?(user) == false,
             "User should not be in users array for container")
      
      # Make sure each user sees the removed groups correctly.
      rm_cn1_groups.each do |group|
        assert(user.groups.include?(group) == false,
               "User should not have group in groups array")
      end
    end
    
    @ad1a.groups.each do |group|
      assert(rm_cn1_groups.include?(group) == false,
             "Group should not be in groups array for container")
      
      # Make sure each group sees the removed users correctly.
      rm_cn1_users.each do |user|
        assert(group.users.include?(user) == false,
               "Group should not have user in users array")
      end
      
      # Make sure each group sees the removed groups correctly.
      rm_cn1_groups.each do |group|
        assert(group.groups.include?(group) == false,
               "Group should not have group in groups array")
      end
    end
    
    # Manually check @rm_cn2 objects to make sure they see all removed objects
    # in their removed_groups and removed_users arrays.
    assert(@rm_wg2.removed_groups.include?(@rm_wg1) == false,
           "wg1 should not be in wg2's removed_groups array")
    assert(@rm_ug2.removed_users.include?(@rm_uu1) == false,
           "uu1 should not be in ug2's removed_users array")
    assert(@rm_wg3.removed_users.include?(@rm_wu1) == false,
           "wu1 should not be in wg3's removed_users array")
    assert(@rm_wu2.removed_groups.include?(@rm_wg1) == false,
           "wg1 should not be in wu2's removed_groups array")
    assert(@rm_uu2.removed_groups.include?(@rm_wg1) == false,
           "wg1 should not be in uu2's removed_groups array")
  end
end
