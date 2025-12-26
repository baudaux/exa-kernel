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


EM_JS(int, lfs_remote_read, (int view_id, int cluster, void * buffer, int size), {
  
	return Asyncify.handleSleep(function (wakeUp) {

	    //console.log("lfs_remote_read: cluster="+cluster+" size="+size);

	    var myInit = {
	      method: 'GET',
	      cache: 'no-store'
	    };

	    const view = window.views[view_id];
	    
	    fetch("/exafs_views/read_cls.php?view="+view+"&cls="+cluster, myInit).then(function (response) {

		if (response.ok) {
	    
		  response.arrayBuffer().then(buf => {

		      const buf2 = new Uint8Array(buf);

		      if (buf2.length > 0) {

			Module.HEAPU8.set(buf2, buffer);
		      }
		      else {

			const buf3 = new Uint8Array(size);
			buf3.fill(0xFF);
			
			Module.HEAPU8.set(buf3, buffer);
		      }
		      
		      wakeUp(0);
		    });
		}
		else {

		  const buf2 = new Uint8Array(size);
		  buf2.fill(0xFF);
		  Module.HEAPU8.set(buf2, buffer);

		  wakeUp(0);
		}
	      }).catch((error) => {

		  wakeUp(-1);
	      
		});

	  });
});

EM_JS(int, lfs_remote_write, (int view_id, int cluster, char * buffer, int size), {
    
      return Asyncify.handleSleep(function (wakeUp) {

	  //console.log("lfs_remote_write: cluster="+cluster+" size="+size);

	  if (window.bulk_mode) {

	    window.bulk_array[window.bulk_size] = cluster & 0xff;
	    window.bulk_array[window.bulk_size+1] = (cluster >> 8) & 0xff;
	    window.bulk_array[window.bulk_size+2] = (cluster >> 16) & 0xff;
	    window.bulk_array[window.bulk_size+3] = (cluster >> 24) & 0xff;

	    window.bulk_array.set(Module.HEAPU8.subarray(buffer, buffer+size), window.bulk_size+4);

	    window.bulk_size += size+4;

	    console.log("lfs_remote_write: bulk size="+window.bulk_size);

	    wakeUp(0);
	  }
	  else {

	    var myInit = {
	    method: 'POST',
	    body: Module.HEAPU8.subarray(buffer, buffer+size)
	    };

	    const view = window.views[view_id];

	    fetch("/exafs_views/write_cls.php?view="+view+"&cls="+cluster, myInit).then(function (response) {

		if (response.ok) {

		  wakeUp(0);
		}
		else {

		  wakeUp(-1);
		}

		//Module.HEAPU8.slice(buffer, buffer+size), off);

	      }).catch((error) => {

		  wakeUp(-1);
	      
		});
	  }
	});
});

EM_JS(int, lfs_remote_bulk_start, (int view_id), {

  window.bulk_mode = 1;
  
  if (typeof window.bulk_array === 'undefined') {
    window.bulk_array = new Uint8Array(20*(16*4096+256+16+4)); // 20 * (cluster size (including tag if encrypted) + id)
  }

  window.bulk_size = 0;
  
  return 0;
});

EM_JS(int, lfs_remote_bulk_end, (int view_id), {

    return Asyncify.handleSleep(function (wakeUp) {

	if (window.bulk_mode) {
	  
	  //console.log("lfs_remote_bulk_end: bulk size="+window.bulk_size);

	  window.bulk_mode = 0;

	  var myInit = {
	    method: 'POST',
	    body: window.bulk_array.subarray(0, window.bulk_size)
	  };

	  const view = window.views[view_id];

	  fetch("/exafs_views/bulk_write.php?view="+view, myInit).then(function (response) {

	      console.log(response);

	      if (response.ok) {

		wakeUp(0);
	      }
	      else {

		wakeUp(-1);
	      }

	      //Module.HEAPU8.slice(buffer, buffer+size), off);

	    }).catch((error) => {

		wakeUp(-1);
	      
	      });

	  }
	else {

	  wakeUp(0);
	}
	});
  
});
