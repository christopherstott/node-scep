#include <dlfcn.h>

#include <node.h>
#include <node_buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace v8;

int (*extract_csr)(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length, char* key_password);
int (*encode_res)(unsigned char* cert_buf, size_t cert_len, unsigned char* p7_buf, size_t p7_len, char *cert, char *key, char **data, size_t &length, char* key_password);
int (*verify)(unsigned char* p7_buf, size_t p7_len, unsigned char* crt_buf, size_t crt_len, unsigned char* in_buf, size_t in_len, char **data, size_t &length );

void Extract_CSR(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    Local<Object> opt = args[0]->ToObject();
    if(!opt->IsObject()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Args[0] must be a buffer")));
      return;
    }

    Local<Value> req = opt->Get(v8::String::NewFromUtf8(isolate, "req", v8::String::kInternalizedString));
    if(!req->IsObject() || !node::Buffer::HasInstance(req)) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "req must be a buffer")));
      return;
    }

    Local<Value> cert = opt->Get(v8::String::NewFromUtf8(isolate, "cert", v8::String::kInternalizedString));
    Local<Value> key = opt->Get(v8::String::NewFromUtf8(isolate, "key", v8::String::kInternalizedString));
    Local<Value> password = opt->Get(v8::String::NewFromUtf8(isolate, "key_password", v8::String::kInternalizedString));

    unsigned char*msg = (unsigned char*) node::Buffer::Data(req);
    size_t msglen = node::Buffer::Length(req);

    v8::String::Utf8Value s4(cert->ToString());
    v8::String::Utf8Value s5(key->ToString());
    v8::String::Utf8Value s6(password->ToString());

    char *data = NULL;
    size_t length = 0;

    extract_csr(msg, msglen, *s4, *s5, &data, length, *s6);

    args.GetReturnValue().Set(node::Buffer::New(data, length));
    return;
}

void Encode_Res(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    Local<Object> opt = args[0]->ToObject();
    Local<Value> crt = opt->Get(v8::String::NewFromUtf8(isolate, "crt", v8::String::kInternalizedString));
    Local<Value> p7 = opt->Get(v8::String::NewFromUtf8(isolate, "req", v8::String::kInternalizedString));
    Local<Value> c = opt->Get(v8::String::NewFromUtf8(isolate, "cert", v8::String::kInternalizedString));
    Local<Value> k = opt->Get(v8::String::NewFromUtf8(isolate, "key", v8::String::kInternalizedString));
    Local<Value> password = opt->Get(v8::String::NewFromUtf8(isolate, "key_password", v8::String::kInternalizedString));
    v8::String::Utf8Value s1(c->ToString());
    v8::String::Utf8Value s2(k->ToString());
    v8::String::Utf8Value s3(password->ToString());

    unsigned char* crt_buf = (unsigned char*) node::Buffer::Data(crt);
    size_t crt_len = node::Buffer::Length(crt);

    unsigned char* p7_buf = (unsigned char*) node::Buffer::Data(p7);
    size_t p7_len = node::Buffer::Length(p7);

    char *data = NULL;
    size_t length = 0;

    encode_res(crt_buf, crt_len, p7_buf, p7_len, *s1, *s2, &data, length, *s3);

    args.GetReturnValue().Set(node::Buffer::New(data, length));
}



void Verify_Response(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    Local<Value> a = args[0];
    if(!a->IsObject() || !node::Buffer::HasInstance(a)) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Args[0] must be a buffer")));
      return;
    }
    Local<Object> pkcs7 = a->ToObject();
    unsigned char* p7_buf = (unsigned char*) node::Buffer::Data(pkcs7);
    size_t p7_len = node::Buffer::Length(pkcs7);

    unsigned char* in_buf = NULL;
    size_t in_len = 0;

    unsigned char* crt_buf = NULL;
    size_t crt_len = 0;

    if (args.Length() == 3) {

       Local<Value> b = args[1];
       if(!b->IsObject() || !node::Buffer::HasInstance(b)) {
         isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Args[1] must be a buffer")));
         return;
       }
       Local<Object> input = b->ToObject();
       in_buf = (unsigned char*) node::Buffer::Data(input);
       in_len = node::Buffer::Length(input);
   
       Local<Value> c = args[2];
       if(!c->IsObject() || !node::Buffer::HasInstance(c)) {
         isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Args[2] must be a buffer")));
         return;
       }
       Local<Object> cert = c->ToObject();
       crt_buf = (unsigned char*) node::Buffer::Data(cert);
       crt_len = node::Buffer::Length(cert);
    }

    char *data = NULL;
    size_t length = 0;
    
    if(verify(p7_buf, p7_len, crt_buf, crt_len, in_buf, in_len, &data, length)) {
      args.GetReturnValue().Set(node::Buffer::New(data, length));
    }
}

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND   0 /* Mac no support  */
#endif

void DlOpen(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    Local<Value> a = args[0];
    if(!a->IsString()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Args[0] must be a string")));
      return;
    }

   v8::String::Utf8Value str(a->ToString());

   void* handle = dlopen(*str, RTLD_NOW | RTLD_DEEPBIND);
   if (!handle) {
       printf("ERROR\n");
   }
   void (*init)(void) = (void(*)(void)) dlsym(handle, "_init_lib");
   std::string n_v = "_verify";
   std::string n_ex = "_extract_csr";
   std::string n_en = "_encode_res";
   if(!init){
      init = (void(*)(void)) dlsym(handle, "init_lib");
      n_v = "verify";
      n_ex = "extract_csr";
      n_en = "encode_res";
   }
   init();
   
   verify = (int(*)(unsigned char* p7_buf, size_t p7_len, unsigned char* crt_buf, size_t crt_len, unsigned char* in_buf, size_t in_len, char **data, size_t &length)) dlsym(handle, n_v.c_str());
   extract_csr = (int(*)(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length, char* key_password)) dlsym(handle, n_ex.c_str());
   encode_res = (int(*)(unsigned char* cert_buf, size_t cert_len, unsigned char* p7_buf, size_t p7_len, char *cert, char *key, char **data, size_t &length, char* key_password )) dlsym(handle, n_en.c_str());
}

void init(Handle<Object> exports) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    exports->Set(String::NewFromUtf8(isolate, "dlopen", v8::String::kInternalizedString), FunctionTemplate::New(isolate, DlOpen)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate, "extract_csr", v8::String::kInternalizedString), FunctionTemplate::New(isolate, Extract_CSR)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate, "encode_res", v8::String::kInternalizedString), FunctionTemplate::New(isolate, Encode_Res)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate, "verify_response", v8::String::kInternalizedString), FunctionTemplate::New(isolate, Verify_Response)->GetFunction());
}

NODE_MODULE(scep, init)
