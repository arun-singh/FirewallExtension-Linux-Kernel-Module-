#ifndef _LINKED_LIST_H
#define _LINKED_LIST_H

typedef struct ListItem {
  char * p_data;
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
List * create_list();

// Appends some data to a list.
void append_list(List *p_list, char * p_data);

// Frees all memory used by a list.
void free_list(List* p_list);

// Remove and free head from list
void free_head(List * p_list);

// Size of list
int total_list_size(List * list);

//data of head element
char * pop_data(List * p_list);

int is_empty(List * p_list);

#endif // _LINKED_LIST_H
