#include <stdlib.h>

#include "unordered_map.h"


struct unordered_map * new_unordered_map(int key, void * data) {

  struct unordered_map * item = (struct unordered_map * )malloc(sizeof(struct unordered_map));

  item->key = key;
  item->data = data;

  item->prev = NULL;
  item->next = NULL;
  
  return item;
}

struct unordered_map * add_item_to_unordered_map(struct unordered_map * unordered_map, int key, void * data) {

  struct unordered_map * item = (struct unordered_map * )malloc(sizeof(struct unordered_map));

  item->key = key;
  item->data = data;

  if (unordered_map->next) {

    unordered_map->next->prev = item;
    item->next = unordered_map->next;
  }
  else {

    item->next = NULL;
  }

  unordered_map->next = item;
  item->prev = unordered_map;
  
  return item;
}

struct unordered_map * remove_item_from_unordered_map(struct unordered_map * unordered_map, struct unordered_map * item) {

  struct unordered_map * prev = item->prev;

  free(item->data);

  if (item->next) {

    item->next->prev = item->prev;
  }
  
  item->prev->next = item->next;
  
  return item->prev;
}

struct unordered_map * remove_item_key_from_unordered_map(struct unordered_map * unordered_map, int key) {

  struct unordered_map * item = get_item_from_unordered_map(unordered_map, key);

  if (item) {

    return remove_item_from_unordered_map(unordered_map, item);
  }
  
  return NULL;
}

struct unordered_map * get_item_from_unordered_map(struct unordered_map * unordered_map, int key) {

  struct unordered_map * item = unordered_map;

  while (item) {

    if (item->key == key)
      return item;

    item = item->next;
  }
  
  return NULL;
}

void destroy_unordered_map(struct unordered_map * unordered_map) {

  struct unordered_map * item = unordered_map;
  struct unordered_map * prev;

  while (item) {

    free(item->data);

    prev = item;
    item = item->next;
    
    free(prev);
  }
}
