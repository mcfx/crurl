#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <string>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/system/sys_info.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "base/values.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "url/gurl.h"

class CrurlDelegate : public net::URLRequest::Delegate {
 public:
  CrurlDelegate();
  ~CrurlDelegate() override;

  void set_on_complete(base::OnceClosure on_complete) {
    on_complete_ = std::move(on_complete);
  }

  void allow_certificate_errors() { allow_certificate_errors_ = true; }

  void set_credentials(net::AuthCredentials credentials) {
    credentials_ = credentials;
  }

  int st() const { return request_status_; }

  const std::string& data_received() const { return data_received_; }

  void OnAuthRequired(net::URLRequest* request,
                      const net::AuthChallengeInfo& auth_info) override;
  void OnSSLCertificateError(net::URLRequest* request,
                             int net_error,
                             const net::SSLInfo& ssl_info,
                             bool fatal) override;
  void OnResponseStarted(net::URLRequest* request, int net_error) override;
  void OnReadCompleted(net::URLRequest* request, int bytes_read) override;

 private:
  static const int kBufferSize = 4096;

  virtual void OnResponseCompleted(net::URLRequest* request);

  bool allow_certificate_errors_ = false;
  net::AuthCredentials credentials_;

  base::OnceClosure on_complete_;
  std::string data_received_;
  int request_status_ = net::ERR_IO_PENDING;
  scoped_refptr<net::IOBuffer> buf_;
};

const int CrurlDelegate::kBufferSize;

CrurlDelegate::CrurlDelegate()
    : buf_(base::MakeRefCounted<net::IOBuffer>(kBufferSize)) {}

CrurlDelegate::~CrurlDelegate() = default;

void CrurlDelegate::OnAuthRequired(net::URLRequest* request,
                                   const net::AuthChallengeInfo& auth_info) {
  if (!credentials_.Empty()) {
    request->SetAuth(credentials_);
  } else {
    request->CancelAuth();
  }
}

void CrurlDelegate::OnSSLCertificateError(net::URLRequest* request,
                                          int net_error,
                                          const net::SSLInfo& ssl_info,
                                          bool fatal) {
  if (allow_certificate_errors_)
    request->ContinueDespiteLastError();
  else
    request->Cancel();
}

void CrurlDelegate::OnResponseStarted(net::URLRequest* request, int net_error) {
  if (net_error != net::OK) {
    OnResponseCompleted(request);
  } else {
    int bytes_read = request->Read(buf_.get(), kBufferSize);
    if (bytes_read >= 0)
      OnReadCompleted(request, bytes_read);
    else if (bytes_read != net::ERR_IO_PENDING)
      OnResponseCompleted(request);
  }
}

void CrurlDelegate::OnReadCompleted(net::URLRequest* request, int bytes_read) {
  if (bytes_read >= 0) {
    data_received_.append(buf_->data(), bytes_read);
  }
  while (bytes_read > 0) {
    bytes_read = request->Read(buf_.get(), kBufferSize);
    if (bytes_read > 0) {
      data_received_.append(buf_->data(), bytes_read);
    }
  }
  request_status_ = bytes_read;
  if (request_status_ != net::ERR_IO_PENDING)
    OnResponseCompleted(request);
}

void CrurlDelegate::OnResponseCompleted(net::URLRequest* request) {
  std::cout << data_received_ << std::flush;
  std::move(on_complete_).Run();
}

constexpr net::NetworkTrafficAnnotationTag tag =
    net::DefineNetworkTrafficAnnotation("crurl", "");

CrurlDelegate delegate;
std::unique_ptr<net::URLRequestContext> context;
std::unique_ptr<net::URLRequest> request;
net::NetLog* net_log;
base::OnceClosure quit;

std::vector<std::pair<std::string, std::string>> headers;
std::string post_data, proxy_string;
GURL url_;
bool is_post = false;

void add_header(const std::string& header) {
  size_t pos = header.find(": ");
  if (pos == std::string::npos)
    return;
  headers.push_back(
      std::make_pair(header.substr(0, pos), header.substr(pos + 2)));
}

void work() {
  net::ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString(proxy_string);
  auto proxy_service =
      net::ConfiguredProxyResolutionService::CreateWithoutProxyResolver(
          std::make_unique<net::ProxyConfigServiceFixed>(
              net::ProxyConfigWithAnnotation(proxy_config, tag)),
          net::NetLog::Get());
  proxy_service->ForceReloadProxyConfig();

  net::URLRequestContextBuilder builder;
  builder.set_proxy_resolution_service(std::move(proxy_service));
  builder.set_enable_brotli(true);
  builder.set_accept_language("en-US,en;q=0.9");
  builder.set_user_agent("curl/7.72.0");

  context = builder.Build();
  request = context->CreateRequest(url_, net::MAXIMUM_PRIORITY, &delegate, tag);

  for (size_t i = 0; i < headers.size(); i++) {
    request->SetExtraRequestHeaderByName(headers[i].first, headers[i].second,
                                         true);
  }

  if (is_post) {
    request->set_method("POST");
    auto reader = std::make_unique<net::UploadBytesElementReader>(
        post_data.c_str(), post_data.size());
    auto upload_data =
        net::ElementsUploadDataStream::CreateWithReader(std::move(reader), 233);
    request->set_upload(std::move(upload_data));
  }

  request->Start();
}

void clear() {
  _exit(0);
  // I don't know how to properly deal with
  // "FATAL:spdy_session.cc(1011) Check failed: !in_io_loop_."
  // request.reset();
  // context.reset();
  // std::move(quit).Run();
}

void set_user(const std::string& user) {
  size_t pos = user.find(":");
  if (pos == std::string::npos)
    return;
  delegate.set_credentials(
      net::AuthCredentials(base::ASCIIToUTF16(user.substr(0, pos)),
                           base::ASCIIToUTF16(user.substr(pos + 1))));
}

void add_post_data(const std::string& data) {
  if (post_data.size())
    post_data.push_back('&');
  post_data += data;
  is_post = true;
}

std::vector<std::string> get_args(int argc, char* argv[]) {
  std::vector<std::string> res;
  for (int i = 0; i < argc; i++) {
    res.push_back(argv[i]);
  }
  return res;
}

void print_help() {
  std::cout
      << "Usage: "
      << base::CommandLine::ForCurrentProcess()->GetProgram().BaseName()
      << " [options...] <url>\n"
         "\n"
         "Options:\n"
         "     --compressed                     No actual meaning\n"
         " -d, --data <data>                    HTTP POST data\n"
         "     --data-binary <data>             HTTP POST data\n"
         "     --data-raw <data>                HTTP POST data\n"
         " -H, --header <header>                Pass custom header(s) to "
         "server\n"
         " -h, --help                           Show this message\n"
         " -k, --insecure                       Allow insecure server "
         "connections when using SSL\n"
         " -x, --proxy [protocol://]host[:port] Use this proxy\n"
         " -u, --user <user:password>           Server user and password\n"
      << std::endl;
}

int main(int argc, char* argv[]) {
  base::FeatureList::InitializeInstance(
      "PartitionConnectionsByNetworkIsolationKey", std::string());
  base::SingleThreadTaskExecutor io_task_executor(base::MessagePumpType::IO);
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("fafa");
  base::AtExitManager exit_manager;
  auto args = get_args(argc, argv);
  base::CommandLine::Init(argc, argv);

  for (size_t i = 1; i < args.size(); i++) {
    const auto& str = args[i];
    if (str.size() > 1 && str[0] == '-') {
      if (str[1] == 'H' && i + 1 < args.size()) {
        add_header(args[++i]);
        continue;
      }
      if (str[1] == 'x' && i + 1 < args.size()) {
        proxy_string = args[++i];
        continue;
      }
      if (str[1] == 'u' && i + 1 < args.size()) {
        set_user(args[++i]);
        continue;
      }
      if (str[1] == 'h') {
        print_help();
        return 0;
      }
      if (str[1] == 'k') {
        delegate.allow_certificate_errors();
        return 0;
      }
      if (str[1] == 'd' && i + 1 < args.size()) {
        add_post_data(args[++i]);
        return 0;
      }
      if (str[1] == '-') {
        if (str.substr(2) == "compressed") {
          continue;
        }
        if (str.substr(2) == "insecure") {
          delegate.allow_certificate_errors();
          continue;
        }
        if (str.substr(2) == "data" && i + 1 < args.size()) {
          add_post_data(args[++i]);
          continue;
        }
        if (str.substr(2) == "data-binary" && i + 1 < args.size()) {
          add_post_data(args[++i]);
          continue;
        }
        if (str.substr(2) == "data-raw" && i + 1 < args.size()) {
          add_post_data(args[++i]);
          continue;
        }
        if (str.substr(2) == "user" && i + 1 < args.size()) {
          set_user(args[++i]);
          continue;
        }
        if (str.substr(2) == "help") {
          print_help();
          return 0;
        }
        if (str.substr(2) == "proxy" && i + 1 < args.size()) {
          proxy_string = args[++i];
          continue;
        }
        if (str.substr(2) == "header" && i + 1 < args.size()) {
          add_header(args[++i]);
          continue;
        }
      }
    }
    url_ = GURL(str);
    if (!url_.is_valid()) {
      url_ = GURL("http://" + str);
    }
  }
  base::RunLoop run_loop;
  quit = run_loop.QuitClosure();
  delegate.set_on_complete(base::BindOnce(clear));

  base::Thread worker_thread("worker");
  base::Thread::Options thread_options(base::MessagePumpType::IO, 0);
  worker_thread.StartWithOptions(std::move(thread_options));
  worker_thread.task_runner()->PostTask(FROM_HERE, base::BindOnce(work));
  run_loop.Run();
  worker_thread.Stop();
}
