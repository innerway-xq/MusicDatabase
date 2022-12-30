var main = function() {
  $('#comment_box').keyup(function() {
    var postLength = $(this).val().length;
    var charactersLeft = 250 - postLength;
    $('.counter').text(charactersLeft);
    if (charactersLeft < 0) {
      $('.btn-primary').addClass('disabled');
    } else if (charactersLeft === 250) {
      $('.btn-primary').addClass('disabled');
    } else {
      $('.btn-primary').removeClass('disabled');
    }
  });
}
$('.btn-primary').addClass('disabled');
$(document).ready(main)