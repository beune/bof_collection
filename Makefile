# List all directories except 'static' and '.git'
DIRS := $(filter-out static/ .git/,$(wildcard */))

.PHONY: all $(DIRS)

all: $(DIRS)

# Run make in each subdirectory
$(DIRS):
	@echo "Entering $@"
	@$(MAKE) -C $@
