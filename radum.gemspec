Gem::Specification.new do |s|
  s.authors = ['Shaun Rowland']
  s.add_dependency('ruby-net-ldap', '= 0.0.4')
  s.description = <<-EOF
    RADUM is a module to manage users and groups in Active Directory uisng pure
    Ruby on any supported platform.
  EOF
  s.email = [ 'rowland@shaunrowland.com' ]
  s.extra_rdoc_files = ['LICENSE']
  s.files = Dir['lib/**/*.rb']
  s.has_rdoc = true
  s.homepage = 'http://www.shaunrowland.com/wiki/RADUM'
  s.name = 'radum'
  s.platform = Gem::Platform::RUBY
  s.rdoc_options << '--exclude' << 'test' <<
                    '--exclude' << 'demo*' <<
                    '--exclude' << 'radum-gemspec.rb' <<
                    '--exclude' << 'lib/radum.rb' <<
                    '--main' << 'RADUM' <<
                    '--accessor' << 'directory' <<
                    '--title' <<
                    'RADUM -- Ruby Active Directory User Management' <<
                    '--line-numbers' <<
                    '--inline-source' <<
                    '--charset=UTF-8'
  s.rubyforge_project = 'radum'
  s.summary = 'Manage users and groups in Active Directory.'
  s.test_files = Dir['test/tc_*.rb']
  s.version = '0.0.2'
end
