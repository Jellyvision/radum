require 'test/unit'
require 'radum'

# This tests the Container class.
class TC_Container < Test::Unit::TestCase
  def setup
    @ad1 = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1 = RADUM::Container.new :name => "ou=People", :directory => @ad1
    @c2_ad1 = RADUM::Container.new :name => "ou=Staff, ou=People",
                                   :directory => @ad1
    @c3_ad1 = RADUM::Container.new :name => "cn=Test", :directory => @ad1
    @c4_ad2 = RADUM::Container.new :name => "cn=Test", :directory => @ad2
    @g1_c1_ad1 = RADUM::Group.new :name => "staff", :container => @c1_ad1
    @g2_c4_ad2 = RADUM::Group.new :name => "enable", :container => @c4_ad2
    @g3_c3_ad1 = RADUM::Group.new :name => "test", :container => @c3_ad1
    @u1_c1_ad1 = RADUM::User.new :username => "user", :container=>  @c1_ad1,
                                 :primary_group => @g1_c1_ad1
    @u2_c4_ad2 = RADUM::User.new :username => "user", :container => @c4_ad2,
                                 :primary_group => @g2_c4_ad2
    @u3_c3_ad1 = RADUM::User.new :username => "remove", :container => @c3_ad1,
                                 :primary_group => @g1_c1_ad1
  end
  
  def test_removed_flag_false
    assert(@c1_ad1.removed? == false, "ad_removed flag should be false")
  end
  
  def test_no_spaces
    assert(@c2_ad1.name.split(/\s+/).length == 1,
           "Should be no spaces in name")
  end
  
  def test_equal_exception
    assert_raise RuntimeError do
      RADUM::Container.new :name => "ou=People", :directory => @ad1
    end
  end
  
  def test_equal_case_insensitive_exception
    assert_raise RuntimeError do
      RADUM::Container.new :name => "ou=people", :directory => @ad1
    end
  end
  
  def test_equal_spaces_exception
    assert_raise RuntimeError do
      RADUM::Container.new :name => "ou=Staff,ou=People", :directory => @ad1
    end
  end
  
  def test_not_equal
    assert(@c1_ad1 != @c3_ad1, "Should not be equal")
  end
  
  def test_not_equal_different_directory
    assert(@c3_ad1 != @c4_ad2, "Should not be equal")
  end
  
  def test_add_user
    assert_block("Should have added exactly one user") do
      # Users add themselves to containers on initialization, so this would be
      # an attempt to add a second time. We want to be totally certain, so the
      # add is done a third time anyway.
      @c1_ad1.add_user @u1_c1_ad1
      @c1_ad1.add_user @u1_c1_ad1
      @c1_ad1.users.length == 1
    end
  end
  
  def test_add_user_removed_flag_manually_set
    assert_block("Should have added exactly one user") do
      # Users add themselves to containers on initialization, so this would be
      # an attempt to add a second time. We want to be totally certain, so the
      # add is done a third time anyway.
      @c1_ad1.add_user @u1_c1_ad1
      @u1_c1_ad1.set_removed
      @c1_ad1.add_user @u1_c1_ad1
      @c1_ad1.users.length == 1
    end
  end
  
  def test_add_user_different_container_exception
    assert_raise RuntimeError do
      @c1_ad1.add_user @u2_c4_ad2
    end
  end
  
  def test_remove_user_different_container_exception
    assert_raise RuntimeError do
      @c1_ad1.remove_user @u3_c3_ad1
    end
  end
  
  def test_remove_user_removed_flag_set
    assert_block("Should have set removed user removed flag") do
      @c1_ad1.remove_user @u1_c1_ad1
      @u1_c1_ad1.removed? == true
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly one group") do
      # Groups add themselves to containers on initialization, so this would be
      # an attempt to add a second time. We want to be totally certain, so the
      # add is done a third time anyway.
      @c1_ad1.add_group @g1_c1_ad1
      @c1_ad1.add_group @g1_c1_ad1
      @c1_ad1.groups.length == 1
    end
  end
  
  def test_add_group_removed_flag_manually_set
    assert_block("Should have added exactly one group") do
      # Groups add themselves to containers on initialization, so this would be
      # an attempt to add a second time. We want to be totally certain, so the
      # add is done a third time anyway.
      @c1_ad1.add_group @g1_c1_ad1
      @g1_c1_ad1.set_removed
      @c1_ad1.add_group @g1_c1_ad1
      @c1_ad1.groups.length == 1
    end
  end
  
  def test_add_group_different_container_exception
    assert_raise RuntimeError do
      # You have to remove a group from its container so that its removed flag
      # is set or the other container will ignore it.
      @c4_ad2.remove_group @g2_c4_ad2
      @c1_ad1.add_group @g2_c4_ad2
    end
  end
  
  def test_remove_group_different_container_exception
    assert_raise RuntimeError do
      @c1_ad1.remove_group @g3_c3_ad1
    end
  end
  
  def test_remove_primary_group_exception
    assert_raise RuntimeError do
      @c1_ad1.remove_group @g1_c1_ad1
    end
  end
  
  def test_remove_unix_main_group_exception
    assert_raise RuntimeError do
      foo = RADUM::UNIXGroup.new :name => "bar", :container => @c3_ad1,
                                 :gid => 1000
      RADUM::UNIXUser.new :username => "foo", :container => @c3_ad1,
                          :primary_group => @g1_c1_ad1, :uid => 1001,
                          :unix_main_group => foo, :shell => "/bin/bash",
                          :home_directory => "/home/foo", :nis_domain => "test",
                          :disabled => false, :rid => 1002
      @c3_ad1.remove_group foo
    end
  end
  
  def test_remove_group_removed_flag_set
    assert_block("Should have set removed group removed flag") do
      @c3_ad1.remove_group @g3_c3_ad1
      @g3_c3_ad1.removed? == true
    end
  end
  
  def test_rid_uid_gid_added_to_container_directory
    assert_block("Should have added UID and GID to directory") do
      bar = RADUM::UNIXGroup.new :name => "bar", :container => @c3_ad1,
                                 :gid => 1001
      RADUM::UNIXUser.new :username => "foo", :container => @c3_ad1,
                          :primary_group => @g1_c1_ad1, :uid => 1000,
                          :unix_main_group => bar, :shell => "/bin/bash",
                          :home_directory => "/home/foo",
                          :nis_domain => "test", :disabled => false,
                          :rid => 1002
      @ad1.uids.find { |uid| uid == 1000 } &&
      @ad1.gids.find { |gid| gid == 1001 } &&
      @ad1.rids.find { |rid| rid == 1002 }
    end
  end
  
  def test_rid_uid_gid_removed_from_container_directory
    assert_block("Should have removed UID and GID from directory") do
      bar = RADUM::UNIXGroup.new :name => "bar", :container => @c3_ad1,
                                 :gid => 1000
      foo = RADUM::UNIXUser.new :username => "foo", :container => @c3_ad1,
                                :primary_group => @g1_c1_ad1, :uid => 1001,
                                :unix_main_group => bar, :shell => "/bin/bash",
                                :home_directory => "/home/foo",
                                :nis_domain => "test", :disabled => false,
                                :rid => 1002
      @c3_ad1.remove_user foo
      @c3_ad1.remove_group bar
      ! (@ad1.uids.find { |uid| uid == 1000 } ||
         @ad1.gids.find { |gid| gid == 1001 } ||
         @ad1.rids.find { |rid| rid == 1002 })
    end
  end
  
  def test_container_with_organizational_unit_exception
    assert_raise RuntimeError do
      RADUM::Container.new :name => "ou=foo,cn=bar", :directory => @ad1
    end
  end
end
