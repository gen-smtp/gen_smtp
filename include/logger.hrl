-ifndef(GEN_SMTP_LOGGER_HRL).
-define(GEN_SMTP_LOGGER_HRL,true).

-include_lib("kernel/include/logger.hrl").

-define(LOG_ERROR_FMT(A),     ?LOG_ERROR(A)).
-define(LOG_WARNING_FMT(A),   ?LOG_WARNING(A)).
-define(LOG_NOTICE_FMT(A),    ?LOG_NOTICE(A)).
-define(LOG_INFO_FMT(A),      ?LOG_INFO(A)).
-define(LOG_DEBUG_FMT(A),     ?LOG_DEBUG(A)).

-define(LOG_ERROR_FMT(A,B),   ?LOG_ERROR(lists:flatten(io_lib:format(A,B)))).
-define(LOG_WARNING_FMT(A,B), ?LOG_WARNING(lists:flatten(io_lib:format(A,B)))).
-define(LOG_NOTICE_FMT(A,B),  ?LOG_NOTICE(lists:flatten(io_lib:format(A,B)))).
-define(LOG_INFO_FMT(A,B),    ?LOG_INFO(lists:flatten(io_lib:format(A,B)))).
-define(LOG_DEBUG_FMT(A,B),   ?LOG_DEBUG(lists:flatten(io_lib:format(A,B)))).

-endif.
