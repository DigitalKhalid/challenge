from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions
from drf_yasg.utils import swagger_auto_schema
from drf_yasg.inspectors import SwaggerAutoSchema


# create class for auto swagger to do nothing
class NoOpSchema(SwaggerAutoSchema):
    def get_operation(self, operation_keys=None):
        return None


# Hide this view from Swagger documentation
@swagger_auto_schema(method='post', auto_schema=NoOpSchema)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    return response.Response({"msg": "Success"}, 200)


# Hide this view from Swagger documentation
@swagger_auto_schema(method='post', auto_schema=NoOpSchema)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    return response.Response({"msg": "Success"}, 200)
