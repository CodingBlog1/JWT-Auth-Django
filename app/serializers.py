from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken,TokenError

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email','username','password']
        
    def validate(self, attrs):
        email = attrs.get('email','')
        username = attrs.get('username','')
        
        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages
            )
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
    
class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6,write_only=True)
    tokens = serializers.SerializerMethodField()
    
   
        
    class Meta:
        model = User
        fields = ['username','password','tokens']


    def get_tokens(self,obj):
        user = User.objects.get(username=obj['username'])
        print(user,'99999999999999')
        return{
            
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }
    def validate(self, attrs):
        username = attrs.get('username','')
        password = attrs.get('password','')
        user = auth.authenticate(username=username,password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }
        

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    print("inside serialiaer")
    def validate(self, attrs):
        print(attrs['refresh'])
        self.refresh_token  = attrs['refresh']
        print(attrs,'aaaaaaaaaaaaaaa')
        return attrs
    def save(self, **kwargs):
        try:
            # RefreshToken(self.token).blacklist()
            refresh_token = RefreshToken(self.refresh_token)
            refresh_token.blacklist()


        except TokenError:
            raise serializers.ValidationError('Invalid refresh token')
