typedef struct ListItem {
  char * p_data;
  int dest;
  
  struct ListItem *p_next;
  struct ListItem *p_previous;
} ListItem;

// Defines a list by its head and tail, to save carting about two
// pointers.
typedef struct List {
  ListItem *p_head;
  ListItem *p_tail;
} List;

// Creates an empty list.
List * create_list(void);

// Appends some data to a list.
void append_list(List *p_list, char * filename, int dest);

// Frees all memory used by a list.
void free_list(List* p_list);

// Remove item from list
int remove_item(List * p_list, ListItem * item);

// Does list contain data
int contains(List * list, void * data);

// Sum message sizes
int total_list_size(List * list);

int is_empty(List * list);

//return message legnth of head
char * pop_data(List * list);

//remove and delete head
void free_head(List * list);

char * findExecutable(void); 
void printRules(void);
void prepString(char * dest, const char* src);
int isProgramAllowed(int dest, char * p_name);