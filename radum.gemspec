Gem::Specification.new do |s|
  s.authors = ['Shaun Rowland']
  s.add_dependency('ruby-net-ldap', '= 0.0.4')
  s.description = <<-EOF
    RADUM is a module to manage users and groups in Active Directory uisng pure
    Ruby on any supported platform.
  EOF
  s.email = [ 'rowland@shaunrowland.com' ]
  # Might want to do this when documentation is expanded.
  #s.extra_rdoc_files = ['README', 'doc/user-guide.txt']
  s.files = Dir['lib/**/*.rb']
  s.files << Dir['test/**/*']
  s.files << Dir['LICENSE']
  s.files << Dir['Notes.txt']
  s.files.delete 'test/run.rb'
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
                    '--line-numbers'
  # Set this once you make a RubyForge project.
  #s.rubyforge_project = 'radum'
  s.summary = 'Manage users and groups in Active Directory.'
  s.test_files = Dir.glob('test/tc_*.rb')
  s.version = '0.0.1'
end
