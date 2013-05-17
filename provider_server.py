import tornado.ioloop
import tornadoredis
import tornado.web
import tornado.gen
from provider import Toroauth2AuthorizationProvider

import logging

class AuthHandler(tornado.web.RequestHandler):
    
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        
        provider = Toroauth2AuthorizationProvider()
        
        result = yield tornado.gen.Task(provider.get_authorization_code_from_uri, self.request.uri)

        if result:
            self.redirect(result['redirect_uri'])          
        else:
            self.write("no response")

class TokenHandler(tornado.web.RequestHandler):
    
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):

        provider = Toroauth2AuthorizationProvider()
    
        data = {k: self.request.arguments[k][0] for k in self.request.arguments.iterkeys()} 

        result = yield tornado.gen.Task(provider.get_token_from_post_data, data)
       
        if result:
            self.finish(result)
        else:
            self.write("no access token")
            
class DevicesHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("devices")

application = tornado.web.Application([
    (r"/oauth/auth", AuthHandler),
    (r"/oauth/token", TokenHandler),
    (r"/devices", DevicesHandler)
])

if __name__ == "__main__":
    application.listen(9999)
    tornado.ioloop.IOLoop.instance().start()

