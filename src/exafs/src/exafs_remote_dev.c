
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

#include "exafs_remote_dev.h"

#include <emscripten.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG

#else
#define emscripten_log(...)
#endif

EM_JS(int, exafs_remote_init_repo, (const char * repo_name, const char * view), {

    //return Asyncify.handleSleep(function (wakeUp) {

	console.log("--> exafs_remote_init_repo: name="+UTF8ToString(repo_name)+", view="+UTF8ToString(view));

	if (typeof window.repo_table === 'undefined') {

	  window.repo_table = new Array();
	}

	window.repo_table.push({name: UTF8ToString(repo_name), view: UTF8ToString(view)});

	  console.log(window.repo_table);
		
	  return window.repo_table.length-1;	

	  //});
  });

EM_JS(int, exafs_remote_clean_repo, (uint32_t ctx_id), {

  return Asyncify.handleSleep(function (wakeUp) {

      console.log("--> exafs_remote_clean_repo");

      const options = {
        method: 'GET',
        cache: 'no-store'
      };

      const view = window.repo_table[ctx_id].view;
      
      fetch("/clean_repo?view="+view, options).then(function (response) {

	  console.log(response);

	  if (response.ok) {
		      
	    wakeUp(0);
	  }
	  else {

	    wakeUp(-1);
	  }
	}).catch((error) => {

	    wakeUp(-1);
	      
	  });
      
    });
  
});

EM_JS(int, exafs_remote_read, (uint32_t ctx_id, uint32_t id, void * buffer, int len, int off), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("--> exafs_remote_read: id="+id+" len="+len);
	
      const options = {
        method: 'GET',
        cache: 'no-store'
      };

      const view = window.repo_table[ctx_id].view;
      
      fetch("/read?view="+view+"&id="+id+"&len="+len, options).then(function (response) {

	  console.log(response);

	  if (response.ok) {

	    response.arrayBuffer().then(buf => {

		const buf2 = new Uint8Array(buf);

		// TODO: To be improved for not receiving the object if len is too small

		if (buf2.length <= len) {
		  
		  Module.HEAPU8.set(buf2, buffer);

		  wakeUp(buf2.length);
		}
		else {
		  
		  wakeUp(-buf2.length);
		}   
		
	      });
	  }
	  else {

	    wakeUp(-1);
	  }
	}).catch((error) => {

	    wakeUp(-1);
	      
	  });

      });
});

EM_JS(int, exafs_remote_read_range, (uint32_t ctx_id, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("--> exafs_remote_read_range: id_min="+id_min+" id_max="+id_max+" len="+len);
	
	const options = {
          method: 'GET',
          cache: 'no-store'
        };

      const view = window.repo_table[ctx_id].view;
      
      fetch("/read_range?view="+view+"&id_min="+id_min+"&id_max="+id_max+"&len="+len, options).then(function (response) {
	  
	  console.log(response);
	  
	  if (response.ok) {

	    response.arrayBuffer().then(buf => {

		const buf2 = new Uint8Array(buf);

		Module.HEAPU8.set(buf2.subarray(0, 4), last_obj);

		const missing_size = buf2[4] | (buf2[5] << 8) | (buf2[6] << 16) | (buf2[7] << 24);

		Module.HEAPU8.set(buf2.subarray(8), buffer);

		if (missing_size == 0) {
		  
		  wakeUp(buf2.length-8);
		}
		else {
		  
		  wakeUp(-missing_size);
		}   
		      
	      });
	  }
	  else {

	    wakeUp(-1);
	  }
	}).catch((error) => {

	    wakeUp(-1);
	});
	  
      });
});

EM_JS(int, exafs_remote_read_set, (uint32_t ctx_id, uint32_t * obj_set, int nb_obj, char * data, int size), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("--> exafs_remote_read_set");

	const view = window.repo_table[ctx_id].view;

	const options = {
	    method: 'POST',
	    headers: {
	      "Content-Type": "application/octet-stream"
	    },
	    body: Module.HEAPU8.subarray(obj_set, obj_set+nb_obj*4)
	};
	
	fetch("/read_set?view="+view+"&nb_obj="+nb_obj+"&size="+size, options).then(function (response) {

	    console.log(response);

	    if (response.ok) {
	      
	      response.arrayBuffer().then(buf => {

		const buf2 = new Uint8Array(buf);

		Module.HEAPU8.set(buf2, data);

		wakeUp(buf2.length);
	      });
	    }
	    else {

	      wakeUp(-1);
	    }
	  }).catch((error) => {

	      wakeUp(-1);
	      
	    });
	    
      });
  });

EM_JS(int, exafs_remote_write, (uint32_t ctx_id, uint32_t id, void * buffer, int len), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("--> exafs_remote_write");

	const view = window.repo_table[ctx_id].view;

	const options = {
	    method: 'POST',
	    headers: {
	      "Content-Type": "application/octet-stream"
	    },
	    body: Module.HEAPU8.subarray(buffer, buffer+len)
	};
	
	fetch("/write?view="+view+"&id="+id, options).then(function (response) {

	    console.log(response);

	    if (response.ok) {
	      
	      wakeUp(len);
	    }
	    else {

	      wakeUp(-1);
	    }
	  }).catch((error) => {

	      wakeUp(-1);
	      
	    });

      });
});

EM_JS(int, exafs_remote_write_range, (uint32_t ctx_id, void * buffer, int len), {
    
});

EM_JS(int, exafs_remote_write_rand, (uint32_t ctx_id, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id), {

    return Asyncify.handleSleep(function (wakeUp) {

	console.log("--> exafs_remote_write_rand");

	const view = window.repo_table[ctx_id].view;

	const options = {
	    method: 'POST',
	    headers: {
	      "Content-Type": "application/octet-stream"
	    },
	    body: Module.HEAPU8.subarray(buffer, buffer+len)
	};
	
	fetch("/write_rand?view="+view+"&max_reserved_id="+max_reserved_id, options).then(function (response) {

	    console.log(response);

	    if (response.ok) {
	      
	      return response.json();
	    }
	    else {

	      wakeUp(-1);
	    }
	  }).then((json) => {

	      console.log(json);

	      Module.HEAPU8[id] = json.id & 0xff;
	      Module.HEAPU8[id+1] = (json.id >> 8) & 0xff;
	      Module.HEAPU8[id+2] = (json.id >> 16) & 0xff;
	      Module.HEAPU8[id+3] = (json.id >> 24) & 0xff;
	      
	      wakeUp(len);

	    }).catch((error) => {

	      wakeUp(-1);
	      
	    });
	
      });
});

EM_JS(int, exafs_remote_delete, (uint32_t ctx_id, uint32_t id), {

    return Asyncify.handleSleep(function (wakeUp) {

	console.log("--> exafs_remote_delete: id="+id);

	const options = {
          method: 'GET',
          cache: 'no-store'
	};

	const view = window.repo_table[ctx_id].view;
      
	fetch("/delete?view="+view+"&id="+id, options).then(function (response) {

	    console.log(response);

	    if (response.ok) {
		      
	      wakeUp(0);
	    }
	    else {

	      wakeUp(-1);
	    }
	  }).catch((error) => {

	      wakeUp(-1);
	      
	    });
	
      });
});

EM_JS(int, exafs_remote_delete_range, (uint32_t ctx_id, uint32_t id_min, uint32_t id_max), {

    return Asyncify.handleSleep(function (wakeUp) {

	console.log("--> exafs_remote_delete_range: id_min="+id_min+", id_max="+id_max);

	const options = {
          method: 'GET',
          cache: 'no-store'
	};

	const view = window.repo_table[ctx_id].view;
      
	fetch("/delete_range?view="+view+"&id_min="+id_min+"&id_max="+id_max, options).then(function (response) {

	    console.log(response);

	    if (response.ok) {
		      
	      wakeUp(0);
	    }
	    else {

	      wakeUp(-1);
	    }
	  }).catch((error) => {

	      wakeUp(-1);
	      
	    });
	
      });
});

EM_JS(int, exafs_remote_delete_set, (uint32_t ctx_id, uint32_t * buffer, int len), {
    
    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("--> exafs_remote_delete_set");

      });
  });
