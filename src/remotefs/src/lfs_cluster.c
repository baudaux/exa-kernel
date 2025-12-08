#include "lfs_block.h"

#include <emscripten.h>

EM_JS(int, lfs_cluster_read, (int view_id, int cluster, void * buffer, int size), {

	//console.log("lfs_cluster_read: cluster="+cluster+" size="+size);
  
	return Asyncify.handleSleep(function (wakeUp) {

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

EM_JS(int, lfs_cluster_write, (int view_id, int cluster, char * buffer, int size), {

    //console.log("lfs_cluster_write: cluster="+cluster+" size="+size);

	return Asyncify.handleSleep(function (wakeUp) {

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
	});
});
