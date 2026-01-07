/*
 * Copyright (C) 2026 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#include "exafs_local_dev.h"

#include <emscripten.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG

#else
#define emscripten_log(...)
#endif

EM_JS(int, exafs_local_read, (struct exafs_ctx * ctx, int id, void * buffer, int len), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_read: id="+id);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_read = (db) => {

	      let store = db.transaction(["blocks"]).objectStore("blocks");
	      
	      let request = store.get(id);
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		if (request.result) {

		  if (request.result.data.length <= len) {

		    Module.HEAPU8.set(request.result.data, buffer);

		    wakeUp(request.result.data.length);
		  }
		  else {

		    Module.HEAPU8.set(request.result.data.subarray(0, len), buffer);
		    
		    wakeUp(len);
		  }
		}
		else {

		  wakeUp(-1);
		}
		
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {

	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("blocks", { keyPath: "block" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_read(window.exafs_local);
		
	      };
	    }
	    else {

	      do_read(window.exafs_local);
	    }

	  });
});

EM_JS(int, exafs_local_write, (struct exafs_ctx * ctx, int id, void * buffer, int len), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_write: id="+id);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_write = (db) => {

	      let store = db.transaction(["blocks"], "readwrite").objectStore("blocks");
	      
	      let request = store.put({block: id, data: Module.HEAPU8.subarray(buffer, buffer+len)});
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		wakeUp(len);
		
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {
	      
	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("blocks", { keyPath: "block" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_write(window.exafs_local);
		
	      };
	    }
	    else {

	      do_write(window.exafs_local);
	    }

      });
});
