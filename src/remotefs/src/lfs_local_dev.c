/*
 * Copyright (C) 2025 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#include <emscripten.h>

#include "lfs_block.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#else
#define emscripten_log(...)
#endif


EM_JS(int, lfs_local_read, (int view_id, int cluster, void * buffer, int size), {
  
    return Asyncify.handleSleep(function (wakeUp) {

	const view = window.views[view_id];

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	console.log("lfs_local_read: view="+view+", cluster="+cluster+", size="+size);

	    let do_read = (db) => {

	      let store = db.transaction(["clusters"]).objectStore("clusters");
	      
	      let request = store.get(cluster);
	      
	      request.onerror = function(event) {

		console.log("lfs_local_read: get cluster -> onerror");

		const buf3 = new Uint8Array(size);
		buf3.fill(0xFF);
		
		Module.HEAPU8.set(buf3, buffer);
		
		wakeUp(0);
	      };
	      
	      request.onsuccess = function(event) {

		console.log("lfs_local_read: get cluster -> onsuccess");

		console.log(event);
		console.log(request);
		console.log(request.result);

		if (request.result) {

		  Module.HEAPU8.set(request.result.data, buffer);
		}
		else {

		  console.log("lfs_local_read: get cluster -> fill with 0xff");
		  
		  const buf3 = new Uint8Array(size);
		  buf3.fill(0xFF);
		
		  Module.HEAPU8.set(buf3, buffer);
		}

		wakeUp(0);
	      };
	    };
	    
	    console.log(Module.localfs_dict);

	    if (typeof Module.localfs_dict === 'undefined') {

	      Module.localfs_dict = {};
	    }

	    if (!(view in Module.localfs_dict)) {

	      console.log("lfs_local_read: open indexedDB");
	      
	      let request = window.indexedDB.open(view, 1);

	      request.onerror = function(event) {

		console.log("lfs_local_read: open indexedDB -> onerror");

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		console.log("lfs_local_read: open indexedDB -> onupgradeneeded");

		let db = event.target.result;

		let objectStore = db.createObjectStore("clusters", { keyPath: "cluster" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		console.log("lfs_local_read: open indexedDB -> onsuccess");
		
		Module.localfs_dict[view] = event.target.result;
		
		do_read(Module.localfs_dict[view]);
		
	      };
	    }
	    else {

	      do_read(Module.localfs_dict[view]);
	    }

	  });
});

EM_JS(int, lfs_local_write, (int view_id, int cluster, char * buffer, int size), {
    
      return Asyncify.handleSleep(function (wakeUp) {

	const view = window.views[view_id];

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    console.log("lfs_local_write: view="+view+", cluster="+cluster+", size="+size);

	    let do_write = (db) => {

	      let store = db.transaction(["clusters"], "readwrite").objectStore("clusters");
	      
	      let request = store.put({cluster: cluster, data: Module.HEAPU8.subarray(buffer, buffer+size)});
	      
	      request.onerror = function(event) {

		console.log("lfs_local_write: put cluster -> onerror");
		
		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		console.log("lfs_local_write: put cluster -> onsuccess");

		console.log(event);
		
		wakeUp(0);
		
	      };
	    };

	    if (typeof Module.localfs_dict === 'undefined') {

	      Module.localfs_dict = {};
	    }

	    if (!(view in Module.localfs_dict)) {
	      
	      let request = window.indexedDB.open(view, 1);

	      console.log("lfs_local_write: open indexedDB");

	      request.onerror = function(event) {

		console.log("lfs_local_write: open indexedDB -> onerror");

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		console.log("lfs_local_write: open indexedDB -> onupgradeneeded");

		let db = event.target.result;

		let objectStore = db.createObjectStore("clusters", { keyPath: "cluster" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		console.log("lfs_local_write: open indexedDB -> onsuccess");
		
		Module.localfs_dict[view] = event.target.result;
		
		do_write(Module.localfs_dict[view]);
		
	      };
	    }
	    else {

	      do_write(Module.localfs_dict[view]);
	    }

	  });
});

EM_JS(int, lfs_local_bulk_start, (int view_id), {

    //do nothing as clusters are written one after another
});

EM_JS(int, lfs_local_bulk_end, (int view_id), {

    // do nothing
});
