$('.confirm_delete').click(function(e){
    e.preventDefault();
    var url = $(this).attr('href');
    swal({
        title: "Are you sure?",
        text: "You will not be able to recover this data!",
        icon: "warning",
        buttons: true,
        dangerMode: true,
    })
    .then((willDelete) => {
        if (willDelete) {
            window.location = url;
        }
    });
    return false;
});

