def wrapper_function(func):
    def decorated_function():
        print("함수 이전에 실행")
        func()
        print("함수 이후에 실행")
    return decorated_function




def basic_function():
    print("실행하고자 하는 함수")


basic_function()

new_function = wrapper_function(basic_function)
new_function()