#include <stdlib.h> 
#include <string.h>           
#include "linked_list.h" 
#include <stdio.h>
#include <string.h>



/* Linked list handling */

List * create_list(){
  List * p_list = malloc(sizeof(List));
  p_list->p_head = NULL;
  p_list->p_tail = NULL;
  return p_list;
}

void append_list(List *p_list, char * p_data) {
  // Allocate some memory for the size of our structure. -- note: edited so struct created out of func
  ListItem *p_new_item = malloc(sizeof(ListItem));
  p_new_item->p_next = NULL;       // We are the new tail -> no p_next.
  p_new_item->p_data = malloc(strlen(p_data)+1);
  strncpy(p_new_item->p_data, p_data, strlen(p_data));     // Set data pointer.
  p_new_item->p_data[strlen(p_data)] = '\0';
 
  // If there is a tail, link it to us; else we must also be the head.
  if (p_list->p_tail!=NULL) {
    p_list->p_tail->p_next = p_new_item;
    p_new_item->p_previous = p_list->p_tail; // Link backwards.
  } else {
    p_list->p_head = p_new_item;
  }                    

  // Now we are the new tail.
  p_list->p_tail = p_new_item;
}

char * pop_data(List * p_list){
    return p_list->p_head->p_data;
}

void free_head(List * p_list){
  ListItem * head = p_list->p_head;
  //list one node long
    if(head == p_list->p_tail){
        p_list->p_head = NULL;
        p_list->p_tail = NULL;
    }else{
    ListItem *next = head->p_next;
      p_list->p_head = next;
    }

    free(head->p_data);
    free(head);
}

int total_list_size(List * list){
  int sum = 0;
  ListItem * curr = list->p_head;
  while(curr!=NULL){
    sum++;
    curr = curr->p_next;
  }
  return sum;
}

void free_list(List* p_list) {
  
  ListItem * head = p_list->p_head;
  ListItem * tmp; 

  if(is_empty(p_list)==0){
    free(p_list);
    return;
  } 

  while((tmp=head)!=NULL){
       head = head->p_next;
       free(tmp->p_data);
       free(tmp);
  }
  free(p_list);
  p_list=NULL;
}

int is_empty(List * p_list){
  if(p_list->p_head==NULL && p_list->p_tail==NULL){
        return 0;
    }
    return 1;
}


