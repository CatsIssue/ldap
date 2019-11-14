CC=gcc
BIT=-m32
CFLAGS=-c -g -Wall $(BIT)
SOURCES=redefined_ldap_connection.c
OBJECTS=$(SOURCES:.c=.o)
LIBRARIES=-lldap -lsasl2
EXECUTABLE=LDAP 


all: $(EXECUTABLE) 
	rsync -av ./ gnivc:ldap_entire/

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(BIT) $^ -o $@ $(LIBRARIES) 

$(OBJECTS): $(SOURCES) 
	cppcheck $(SOURCES)
	$(CC) $(CFLAGS) $^ 
	
clean: 
	rm -rf $(EXECUTABLE) $(OBJECTS) 



