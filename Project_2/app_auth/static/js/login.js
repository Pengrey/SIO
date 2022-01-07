window.onload = function() {

$('#sign_up').click(function(){
    $('#modal').css('display','block');
    $('.modal-bg').css('z-index','100');
    $('.modal-bg').fadeIn();
});

  $('#close').click(function(){
        $('.modal-bg').fadeOut();		
        $('#modal').fadeOut();
    return false;
  });
};