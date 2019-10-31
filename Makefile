CC=gcc
CFLAGS=-c -g
SOURCES=redefined_ldap_connection.c
OBJECTS=$(SOURCES:.c=.o)
LIBRARIES=-lldap	
EXECUTABLE=LDAP 


all: $(EXECUTABLE) 

$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ $(LIBRARIES) 

$(OBJECTS): $(SOURCES) 
	cppcheck $(SOURCES)
	$(CC) $(CFLAGS) $^ 

clean: 
	rm -rf *.o build



