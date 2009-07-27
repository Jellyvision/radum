require 'test/unit'
require 'radum'

# This tests the UNIXUser class.
class TC_UNIXUser < Test::Unit::TestCase
  def setup
    @ad1 = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1 = RADUM::Container.new :name => "ou=People", :directory => @ad1
    @c2_ad2 = RADUM::Container.new :name => "ou=Staff,ou=People",
                                   :directory => @ad2
    @ug1_c1_ad1 = RADUM::UNIXGroup.new :name => "staff", :container => @c1_ad1,
                                       :gid => 1001
    @ug2_c1_ad1 = RADUM::UNIXGroup.new :name => "enable", :container => @c1_ad1,
                                       :gid => 1002
    @ug3_c2_ad2 = RADUM::UNIXGroup.new :name => "enable", :container => @c2_ad2,
                                       :gid => 1003
    @g4_c1_ad1 = RADUM::Group.new :name => "class", :container => @c1_ad1
    @uu1a_c1_ad1 = RADUM::UNIXUser.new :username => "user",
                                       :container => @c1_ad1,
                                       :primary_group => @g4_c1_ad1,
                                       :uid => 1000,
                                       :unix_main_group => @ug1_c1_ad1,
                                       :shell => "/bin/bash",
                                       :home_directory => "/home/user"
  end
  
  def test_removed_flag_false
    assert(@uu1a_c1_ad1.removed? == false, "Removed flag should be false")
  end
  
  def test_duplicate_uid_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new :username => "test", :container => @c1_ad1,
                          :primary_group => @g4_c1_ad1, :uid => 1000,
                          :unix_main_group => @ug1_c1_ad1,
                          :shell => "/bin/bash",
                          :home_directory => "/home/user"
    end
  end
  
  def test_unix_main_group_different_directory_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new :username => "test", :container => @c1_ad1,
                          :primary_group => @g4_c1_ad1, :uid => 1000,
                          :unix_main_group => @ug3_c2_ad2,
                          :shell => "/bin/bash",
                          :home_directory => "/home/test"
    end
  end
  
  def test_unix_main_group_non_unix_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new :username => "test", :container => @c1_ad1,
                          :primary_group => @g4_c1_ad1, :uid => 1000,
                          :unix_main_group => @g4_c1_ad1,
                          :shell => "/bin/bash",
                          :home_directory => "/home/test"
    end
  end
  
  def test_removed_unix_main_group_exception
    assert_raise RuntimeError do
      @ug2_c1_ad1.set_removed
      @uu1a_c1_ad1.unix_main_group = @ug2_c1_ad1
    end
  end
  
  def test_add_unix_group_different_directory_exception
    assert_raise RuntimeError do
      @uu1a_c1_ad1.add_group @ug3_c2_ad2
    end
  end
  
  def test_add_unix_group_no_exception
    assert_nothing_raised do
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly one group") do
      # Note that the UNIXUser already added its unix_main_group, so the count
      # should be two (so it should have really added a total of two groups
      # only).
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
      @uu1a_c1_ad1.groups.length == 2 &&
      @uu1a_c1_ad1.groups.find { |group| group == @ug2_c1_ad1 }
    end
  end
  
  def test_remove_unix_main_group_exception
    assert_raise RuntimeError do
      @uu1a_c1_ad1.remove_group @ug1_c1_ad1
    end
  end
end
