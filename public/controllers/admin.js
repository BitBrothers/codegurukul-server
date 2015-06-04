angular.module('Codegurukul')
    .controller('AdminCtrl', function($scope, $alert, $rootScope, Admin, $state) {

    Admin.default.query(function(data) {
        $scope.courses = data;
        console.log($scope.courses);
    })

    $scope.createCourseModalShown = false;

    $scope.createCourseModal = function(){
        $scope.createCourseModalShown = !$scope.createCourseModalShown;
    }


    //    $scope.courseName = "";
    $scope.createCourse = function(){
        console.log("here "+ $scope.courseName);
        Admin.create.save({
            name: $scope.courseName
        },function(data){
            $alert({
                content: 'Course successfully created.',
                placement: 'right',
                type: 'success',
                duration: 5
            });
            $scope.createCourseModal();
            $state.reload();
        },function(error){
            $alert({
                content: 'There was an error. Please try again later.',
                placement: 'right',
                type: 'danger',
                duration: 5
            });
        });
    };

});