/*
 * Copyright (C) 2023 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _UNORDERED_MAP_H

struct unordered_map {

  int key;
  void * data;
  struct unordered_map * prev;
  struct unordered_map * next;
};

struct unordered_map * new_unordered_map(int key, void * data);

struct unordered_map * add_item_to_unordered_map(struct unordered_map * unordered_map, int key, void * data);

struct unordered_map * remove_item_from_unordered_map(struct unordered_map * unordered_map, struct unordered_map * item);

struct unordered_map * remove_item_key_from_unordered_map(struct unordered_map * unordered_map, int key);

struct unordered_map * get_item_from_unordered_map(struct unordered_map * unordered_map, int key);

void destroy_unordered_map(struct unordered_map * unordered_map);

#endif // _UNORDERED_MAP_H
