define _enum-parent-dirs
$(if $(1),$(1) $(if $(filter / ./,$(dir $(1))),,$(call enum-parent-dirs,$(dir $(1)))),)
endef

define enum-parent-dirs
$(call _enum-parent-dirs,$(patsubst %/,%,$(1)))
endef

define reverse
$(if $(1),$(call reverse,$(wordlist 2,$(words $(1)),$(1)))) $(firstword $(1))
endef

# Returns the list of all existing output directories up to $(O) including all
# intermediate levels, in depth first order so that rmdir can process them in
# order. May return an empty string.
# Example: if cleandirs is "foo/a foo/b/c/d" and O=foo, this will return
# "foo/b/c/d foo/b/c foo/b foo/a" (assuming all exist).
define cleandirs-for-rmdir
$(wildcard $(addprefix $(O)/,
		       $(call reverse,$(sort
			   $(foreach dir,$(patsubst $(O)/%,%,$(cleandirs)),
					 $(call enum-parent-dirs,$(dir)))))))
endef

