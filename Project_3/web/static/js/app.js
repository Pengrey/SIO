$( document ).ready(function() {
  
 $("button#login").click(function(){
         $.ajax({
     		type: "POST",
 			url: "/login",
			data: $('#loginform').serialize(),
         		success: function(msg){
                  window.location = "/upload";
         	},
			 error: function(){
				 alert("Authentication failed");
 			}
       	});
   	  });
});
