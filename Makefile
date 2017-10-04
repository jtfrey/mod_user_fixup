
APACHE_PREFIX     = /usr
APACHE_BIN        = $(APACHE_PREFIX)/bin
APXS              = $(APACHE_BIN)/apxs

TARGET            = mod_user_fixup.so

SOURCES           = mod_user_fixup.c

#

$(TARGET): $(SOURCES)
	$(APXS) -c -o $(TARGET) $(LD_EXTRAS) $(SOURCES)

clean::
	rm -f $(TARGET) *.o

install:: 
	$(APXS) -i -a -c $(LD_EXTRAS) $(SOURCES)
