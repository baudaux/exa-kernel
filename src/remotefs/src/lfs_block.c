#include "lfs_block.h"

#include <emscripten.h>

void lfs_blk_set(const char * view) {

  EM_ASM({

      window.view = UTF8ToString($0, $1);

      console.log("lfs_block: view="+window.view);
	  
    }, view, strlen(view));
}

EM_JS(int, lfs_blk_read, (const struct lfs_config * c, lfs_block_t block,
			 lfs_off_t off, void * buffer, lfs_size_t size), {

	console.log("lfs_blk_read: block="+block+" off="+off+" size="+size);
  
	return Asyncify.handleSleep(function (wakeUp) {

	    var myInit = {
	      method: 'GET',
	      cache: 'no-store'
	    };
	    
	    fetch("/exafs_views/read_blk.php?view="+window.view+"&blk="+block, myInit).then(function (response) {

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

EM_JS(int, lfs_blk_prog, (const struct lfs_config * c, lfs_block_t block,
			  lfs_off_t off, const void * buffer, lfs_size_t size), {

	console.log("lfs_blk_prog: block="+block+" off="+off+" size="+size);

	return Asyncify.handleSleep(function (wakeUp) {

	    var myInit = {
	      method: 'POST',
	      body: Module.HEAPU8.subarray(buffer, buffer+size)
	    };

	    fetch("/exafs_views/prog_blk.php?view="+window.view+"&blk="+block, myInit).then(function (response) {

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

EM_JS(int, lfs_blk_erase, (const struct lfs_config * c, lfs_block_t block), {

    console.log("lfs_blk_erase: block="+block);

    return Asyncify.handleSleep(function (wakeUp) {

	var myInit = {
	      method: 'GET',
	      cache: 'no-store'
	    };
	
	fetch("/exafs_views/erase_blk.php?view="+window.view+"&blk="+block, myInit).then(function (response) {
	    
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

int lfs_blk_sync(const struct lfs_config * c) {

  //emscripten_log(EM_LOG_CONSOLE,"*** lfs_blk_sync");
  
  return 0;
}
