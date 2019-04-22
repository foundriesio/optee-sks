global-incdirs-y += include
global-incdirs-y += src
subdirs-y += src

CFG_SKS_TA_TOKEN_COUNT ?= 3
CPPFLAGS += -DCFG_SKS_TA_TOKEN_COUNT=$(CFG_SKS_TA_TOKEN_COUNT)
