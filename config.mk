# Default output directory.
# May be absolute, or relative to the optee_client source directory.
O               ?= out

# To be used instead of $(O) in sub-directories
OO := $(if $(filter /%,$(O)),$(O),$(CURDIR)/../$(O))
