#include "handlers.h"

#include <vector>

#include "rendering.h"

#include <fstream>

// register an orm mapping (to convert the db query results into
// json objects).
// the db query results contain several rows, each has a number of
// fields. the order of `make_db_field<Type[i]>(name[i])` in the
// initializer list corresponds to these fields (`Type[0]` and
// `name[0]` correspond to field[0], `Type[1]` and `name[1]`
// correspond to field[1], ...). `Type[i]` is the type you want
// to convert the field value to, and `name[i]` is the identifier
// with which you want to store the field in the json object, so
// if the returned json object is `obj`, `obj[name[i]]` will have
// the type of `Type[i]` and store the value of field[i].
bserv::db_relation_to_object orm_user{
	bserv::make_db_field<int>("id"),
	bserv::make_db_field<std::string>("username"),
	bserv::make_db_field<std::string>("password"),
	bserv::make_db_field<bool>("is_superuser"),
	bserv::make_db_field<std::string>("first_name"),
	bserv::make_db_field<std::string>("last_name"),
	bserv::make_db_field<std::string>("email"),
	bserv::make_db_field<bool>("is_active"),
	bserv::make_db_field<int>("is_musician")
};

bserv::db_relation_to_object orm_music{
	bserv::make_db_field<int>("music_id"),
	bserv::make_db_field<std::string>("musician"),
	bserv::make_db_field<std::string>("music_name"),
	bserv::make_db_field<std::string>("music_path"),
	bserv::make_db_field<bool>("is_active")
};

bserv::db_relation_to_object orm_comment{
	bserv::make_db_field<int>("comment_id"),
	bserv::make_db_field<std::string>("username"),
	bserv::make_db_field<std::string>("comment_time"),
	bserv::make_db_field<std::string>("comment_content"),
};

std::optional<boost::json::object> get_user(
	bserv::db_transaction& tx,
	const boost::json::string& username) {
	bserv::db_result r = tx.exec(
		"select * from auth_user where username = ?", username);
	lginfo << r.query(); // this is how you log info
	return orm_user.convert_to_optional(r);
}

std::string get_or_empty(
	boost::json::object& obj,
	const std::string& key) {
	return obj.count(key) ? obj[key].as_string().c_str() : "";
}

// if you want to manually modify the response,
// the return type should be `std::nullopt_t`,
// and the return value should be `std::nullopt`.
std::nullopt_t hello(
	bserv::response_type& response,
	std::shared_ptr<bserv::session_type> session_ptr) {
	bserv::session_type& session = *session_ptr;
	boost::json::object obj;
	if (session.count("user")) {
		// NOTE: modifications to sessions must be performed
		// BEFORE referencing objects in them. this is because
		// modifications might invalidate referenced objects.
		// in this example, "count" might be added to `session`,
		// which should be performed first.
		// then `user` can be referenced safely.
		if (!session.count("count")) {
			session["count"] = 0;
		}
		auto& user = session["user"].as_object();
		session["count"] = session["count"].as_int64() + 1;
		obj = {
			{"welcome", user["username"]},
			{"count", session["count"]}
		};
	}
	else {
		obj = { {"msg", "hello, world!"} };
	}
	// the response body is a string,
	// so the `obj` should be serialized
	response.body() = boost::json::serialize(obj);
	response.prepare_payload(); // this line is important!
	return std::nullopt;
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::object user_register(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("username") == 0 || params["username"].as_string() == "") {
		return {
			{"success", false},
			{"message", "`username` is required"}
		};
	}
	if (params.count("password") == 0 || params["password"].as_string() == "") {
		return {
			{"success", false},
			{"message", "`password` is required"}
		};
	}
	auto username = params["username"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user(tx, username);
	if (opt_user.has_value()) {
		return {
			{"success", false},
			{"message", "`username` existed"}
		};
	}
	auto password = params["password"].as_string();
	bserv::db_result r = tx.exec(
		"insert into ? "
		"(?, password, is_superuser, "
		"first_name, last_name, email, is_active) values "
		"(?, ?, ?, ?, ?, ?, ?);", bserv::db_name("auth_user"),
		bserv::db_name("username"),
		username,
		bserv::utils::security::encode_password(
			password.c_str()), false,
		get_or_empty(params, "first_name"),
		get_or_empty(params, "last_name"),
		get_or_empty(params, "email"), true);
	lginfo << r.query();
	tx.commit(); // you must manually commit changes
	return {
		{"success", true},
		{"message", "user registered"}
	};
}

boost::json::object user_login(
	bserv::request_type& request,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("username") == 0) {
		return {
			{"success", false},
			{"message", "`username` is required"}
		};
	}
	if (params.count("password") == 0) {
		return {
			{"success", false},
			{"message", "`password` is required"}
		};
	}
	auto username = params["username"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user(tx, username);
	if (!opt_user.has_value()) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	auto& user = opt_user.value();
	if (!user["is_active"].as_bool()) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	auto password = params["password"].as_string();
	auto encoded_password = user["password"].as_string();
	if (!bserv::utils::security::check_password(
		password.c_str(), encoded_password.c_str())) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	bserv::session_type& session = *session_ptr;
	session["user"] = user;
	return {
		{"success", true},
		{"message", "login successfully"}
	};
}

boost::json::object find_user(
	std::shared_ptr<bserv::db_connection> conn,
	const std::string& username) {
	bserv::db_transaction tx{ conn };
	auto user = get_user(tx, username.c_str());
	if (!user.has_value()) {
		return {
			{"success", false},
			{"message", "requested user does not exist"}
		};
	}
	user.value().erase("id");
	user.value().erase("password");
	return {
		{"success", true},
		{"user", user.value()}
	};
}

boost::json::object user_logout(
	std::shared_ptr<bserv::session_type> session_ptr) {
	bserv::session_type& session = *session_ptr;
	if (session.count("user")) {
		session.erase("user");
	}
	return {
		{"success", true},
		{"message", "logout successfully"}
	};
}

boost::json::object add_music(
	bserv::request_type& request,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	//¼ì²éÊÇ·ñÎªmusician
	bserv::session_type& session = *session_ptr;
	if (!session.count("user")) {
		return {
			{"success", false},
			{"message", "please login first"}
		};
	}
	auto& now_user = session["user"].as_object();
	if (now_user["is_musician"].as_int64() != 2) {
		return {
			{"success", false},
			{"message", "not musician"}
		};
	}
	auto musician_id = now_user["id"].as_int64();

	std::string music_name = "", music_file = "", music_path = "";
	std::stringstream ssdata(request.body());
	std::string tmp;
	for (int i = 0; i < 3; ++i)
		std::getline(ssdata, tmp);
	std::getline(ssdata, tmp);
	music_name = tmp;
	if (music_name[music_name.length()-1] == '\r')
		music_name.erase(music_name.length()-1);
	lgdebug << "music_name: " << music_name;
	std::getline(ssdata, tmp);
	std::getline(ssdata, tmp);
	tmp.erase(tmp.find_last_of('\"'));
	tmp = tmp.substr(tmp.find_last_of('\"')+1);
	music_file = tmp;
	lgdebug << music_file;
	if (music_name == "") {
		return {
			{"success", false},
			{"message", "`music_name` is required"}
		};
	}
	if (music_file == "") {
		return {
			{"success", false},
			{"message", "`music_file` is required"}
		};
	}

	bserv::db_transaction tx{ conn };
	bserv::db_result db_res = tx.exec("select * from music_music_id_seq;");
	int seq = 1;
	if((*db_res.begin())[2].as<bool>())
		seq = (*db_res.begin())[0].as<int>() + 1;
	music_file = std::to_string(seq) + music_file.substr(music_file.find_last_of('.'));
	music_path = "../templates/statics/musics/" + music_file;
	lgdebug << "music_path: " << music_path;

	bserv::db_result r = tx.exec(
		"insert into ? "
		"(musician_id, music_name, music_path)"
		"values (?, ?, ?);", bserv::db_name("music"),
		musician_id,
		music_name,
		music_file);
	lginfo << r.query();
	tx.commit(); // you must manually commit changes

	std::string file_data = request.body();
	file_data = file_data.substr(file_data.find("Content-Type: "));
	file_data = file_data.substr(file_data.find('\n')+1);
	file_data = file_data.substr(file_data.find('\n')+1);

	for (int i = 0; i < 2; ++i) {
		int pos = file_data.find_last_of('\n');
		file_data.erase(pos);
	}
	if (file_data[file_data.length() - 1] == '\r')
		file_data.erase(file_data.length() - 1);

	std::ofstream fout;
	fout.open(music_path, std::ios::out | std::ios::binary);
	for (char i : file_data)
		fout << i;
	fout.close();
	return {
		{"success", true},
		{"message", "music added"}
	};
}

boost::json::object load_music(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	int music_id,
	boost::json::object &context) {
	boost::json::object json_music;
	bserv::db_transaction tx{ conn };
	bserv::db_result db_res;
	db_res = tx.exec("select music_id, username musician, music_name, music_path, music.is_active"
		" from music join auth_user on music.musician_id=auth_user.id where music_id = ?;", music_id);
	lginfo << db_res.query();
	auto opt_music = orm_music.convert_to_optional(db_res);
	if (!opt_music.has_value()) {
		return {
			{"success", false},
			{"message", "no such music"}
		};
	}
	auto& music = opt_music.value();
	if (!music["is_active"].as_bool()) {
		return {
			{"success", false},
			{"message", "no such music"}
		};
	}
	lgdebug << "music_name: " << music["music_name"].as_string();
	json_music["music_name"] = music["music_name"].as_string();
	lgdebug << "musician: " << music["musician"];
	json_music["musician"] = music["musician"];
	std::string music_path = "/statics/musics/";
	music_path += music["music_path"].as_string();
	lgdebug << "music_path: " << music_path;
	json_music["music_path"] = music_path;
	json_music["music_id"] = music["music_id"].as_int64();
	bserv::session_type& session = *session_ptr;
	lgdebug << json_music;
	session["music"] = json_music;
	context["music"] = json_music;
	return context;
}

boost::json::object post_comment(
	bserv::request_type& request,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	boost::json::object&& params,
	int& music_id) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	bserv::session_type& session = *session_ptr;
	boost::json::object json_music = session["music"].as_object();
	music_id = json_music["music_id"].as_int64();
	if (!session.count("user")) {
		return {
			{"success", false},
			{"message", "please login first"}
		};
	}
	boost::json::object json_user = session["user"].as_object();
	int user_id = json_user["id"].as_int64();
	std::time_t now = std::time(NULL);
	bserv::db_transaction tx{ conn };
	bserv::db_result r = tx.exec(
		"insert into comment(user_id, music_id, comment_time, comment_content) values "
		"(?, ?, to_timestamp(?), ?);",
		user_id,
		music_id,
		now,
		get_or_empty(params, "comment_box"));
	lginfo << r.query();
	tx.commit();
	return {
		{"success", true},
		{"message", "comment posted"}
	};
}

boost::json::object send_request(
	std::shared_ptr<bserv::session_type> session,
	std::shared_ptr<bserv::http_client> client_ptr,
	boost::json::object&& params) {
	// post for response:
	// auto res = client_ptr->post(
	//     "localhost", "8080", "/echo", {{"msg", "request"}}
	// );
	// return {{"response", boost::json::parse(res.body())}};
	// -------------------------------------------------------
	// - if it takes longer than 30 seconds (by default) to
	// - get the response, this will raise a read timeout
	// -------------------------------------------------------
	// post for json response (json value, rather than json
	// object, is returned):
	auto obj = client_ptr->post_for_value(
		"localhost", "8080", "/echo", { {"request", params} }
	);
	if (session->count("cnt") == 0) {
		(*session)["cnt"] = 0;
	}
	(*session)["cnt"] = (*session)["cnt"].as_int64() + 1;
	return { {"response", obj}, {"cnt", (*session)["cnt"]} };
}

boost::json::object echo(
	boost::json::object&& params) {
	return { {"echo", params} };
}

// websocket
std::nullopt_t ws_echo(
	std::shared_ptr<bserv::session_type> session,
	std::shared_ptr<bserv::websocket_server> ws_server) {
	ws_server->write_json((*session)["cnt"]);
	while (true) {
		try {
			std::string data = ws_server->read();
			ws_server->write(data);
		}
		catch (bserv::websocket_closed&) {
			break;
		}
	}
	return std::nullopt;
}


std::nullopt_t serve_static_files(
	bserv::response_type& response,
	const std::string& path) {
	response.set(bserv::http::field::accept_ranges, "bytes");
	return serve(response, path);
}


std::nullopt_t index(
	const std::string& template_path,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	boost::json::object& context) {
	bserv::session_type& session = *session_ptr;
	if (session.contains("user")) {
		context["user"] = session["user"];
	}
	return render(response, template_path, context);
}

std::nullopt_t index_page(
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response) {
	boost::json::object context;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t form_login(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	lgdebug << params << std::endl;
	auto context = user_login(request, std::move(params), conn, session_ptr);
	lginfo << "login: " << context << std::endl;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t form_logout(
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response) {
	auto context = user_logout(session_ptr);
	lginfo << "logout: " << context << std::endl;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t redirect_to_users(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	int page_id,
	boost::json::object&& context) {
	lgdebug << "view users: " << page_id << std::endl;
	bserv::db_transaction tx{ conn };
	bserv::db_result db_res = tx.exec("select count(*) from auth_user;");
	lginfo << db_res.query();
	std::size_t total_users = (*db_res.begin())[0].as<std::size_t>();
	lgdebug << "total users: " << total_users << std::endl;
	int total_pages = (int)total_users / 10;
	if (total_users % 10 != 0) ++total_pages;
	lgdebug << "total pages: " << total_pages << std::endl;
	db_res = tx.exec("select * from auth_user limit 10 offset ?;", (page_id - 1) * 10);
	lginfo << db_res.query();
	auto users = orm_user.convert_to_vector(db_res);
	boost::json::array json_users;
	for (auto& user : users) {
		json_users.push_back(user);
	}
	boost::json::object pagination;
	if (total_pages != 0) {
		pagination["total"] = total_pages;
		if (page_id > 1) {
			pagination["previous"] = page_id - 1;
		}
		if (page_id < total_pages) {
			pagination["next"] = page_id + 1;
		}
		int lower = page_id - 3;
		int upper = page_id + 3;
		if (page_id - 3 > 2) {
			pagination["left_ellipsis"] = true;
		}
		else {
			lower = 1;
		}
		if (page_id + 3 < total_pages - 1) {
			pagination["right_ellipsis"] = true;
		}
		else {
			upper = total_pages;
		}
		pagination["current"] = page_id;
		boost::json::array pages_left;
		for (int i = lower; i < page_id; ++i) {
			pages_left.push_back(i);
		}
		pagination["pages_left"] = pages_left;
		boost::json::array pages_right;
		for (int i = page_id + 1; i <= upper; ++i) {
			pages_right.push_back(i);
		}
		pagination["pages_right"] = pages_right;
		context["pagination"] = pagination;
	}
	context["users"] = json_users;
	return index("users.html", session_ptr, response, context);
}

std::nullopt_t redirect_to_music_repo(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	int page_id,
	boost::json::object&& context) {
	lgdebug << "view music_repo: " << page_id << std::endl;
	bserv::db_transaction tx{ conn };
	bserv::db_result db_res = tx.exec("select count(*) from music where is_active = true;");
	lginfo << db_res.query();
	std::size_t total_music_repo = (*db_res.begin())[0].as<std::size_t>();
	lgdebug << "total music_repo: " << total_music_repo << std::endl;
	int total_pages = (int)total_music_repo / 10;
	if (total_music_repo % 10 != 0) ++total_pages;
	lgdebug << "total pages: " << total_pages << std::endl;
	db_res = tx.exec("select * from music where is_active = true limit 10 offset ?;", (page_id - 1) * 10);
	lginfo << db_res.query();
	auto music_repo = orm_music.convert_to_vector(db_res);
	boost::json::array json_music_repo;
	for (auto& music : music_repo) {
		json_music_repo.push_back(music);
	}
	boost::json::object pagination;
	if (total_pages != 0) {
		pagination["total"] = total_pages;
		if (page_id > 1) {
			pagination["previous"] = page_id - 1;
		}
		if (page_id < total_pages) {
			pagination["next"] = page_id + 1;
		}
		int lower = page_id - 3;
		int upper = page_id + 3;
		if (page_id - 3 > 2) {
			pagination["left_ellipsis"] = true;
		}
		else {
			lower = 1;
		}
		if (page_id + 3 < total_pages - 1) {
			pagination["right_ellipsis"] = true;
		}
		else {
			upper = total_pages;
		}
		pagination["current"] = page_id;
		boost::json::array pages_left;
		for (int i = lower; i < page_id; ++i) {
			pages_left.push_back(i);
		}
		pagination["pages_left"] = pages_left;
		boost::json::array pages_right;
		for (int i = page_id + 1; i <= upper; ++i) {
			pages_right.push_back(i);
		}
		pagination["pages_right"] = pages_right;
		context["pagination"] = pagination;
	}
	context["music_repo"] = json_music_repo;
	return index("music_repo.html", session_ptr, response, context);
}

std::nullopt_t redirect_to_music(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	int music_id,
	boost::json::object&& context) {
	lgdebug << "view music: " << music_id << std::endl;
	bserv::db_transaction tx{ conn };
	bserv::db_result db_res = tx.exec("select comment_id, username, comment_time, comment_content"
		" from comment join auth_user on comment.user_id=auth_user.id where music_id = ?;", music_id);
	lginfo << db_res.query();
	auto comments = orm_comment.convert_to_vector(db_res);
	boost::json::array json_comments;
	for (auto& comment : comments) {
		lgdebug << comment;
		json_comments.push_back(comment);
	}
	context["comments"] = json_comments;
	return index("music.html", session_ptr, response, context);
}

std::nullopt_t view_users(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	const std::string& page_num) {
	int page_id = std::stoi(page_num);
	boost::json::object context;
	return redirect_to_users(conn, session_ptr, response, page_id, std::move(context));
}

std::nullopt_t form_add_user(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	boost::json::object context = user_register(request, std::move(params), conn);
	return redirect_to_users(conn, session_ptr, response, 1, std::move(context));
}

std::nullopt_t view_music_repo(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	const std::string& page_num) {
	int page_id = std::stoi(page_num);
	boost::json::object context;
	return redirect_to_music_repo(conn, session_ptr, response, page_id, std::move(context));
}

std::nullopt_t form_add_music(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	boost::json::object context = add_music(request, std::move(params), conn, session_ptr);
	return redirect_to_music_repo(conn, session_ptr, response, 1, std::move(context));
}

std::nullopt_t view_music(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	const std::string& music_id) {
	boost::json::object context;
	load_music(conn, session_ptr, std::stoi(music_id), context);
	return redirect_to_music(conn, session_ptr, response, std::stoi(music_id), std::move(context));
}

std::nullopt_t form_post_comment(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	int music_id;
	boost::json::object context = post_comment(request, conn, session_ptr, std::move(params), music_id);
	load_music(conn, session_ptr, music_id, context);
	return redirect_to_music(conn, session_ptr, response, music_id, std::move(context));
}