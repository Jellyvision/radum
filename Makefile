doc:
	@rdoc --exclude test --main ActiveDirectory --accessor directory

clean:
	@rm -rf doc
