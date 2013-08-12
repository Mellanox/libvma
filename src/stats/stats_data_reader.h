

#ifndef STATS_DATA_READER_H
#define STATS_DATA_READER_H


typedef std::map< void*, std::pair<void*, int> > stats_read_map_t;


typedef struct {
        int size;
        void* shm_addr;

} data_addr_and_size_t;

class stats_data_reader :  
        public timer_handler

{
        public:
                stats_data_reader();
                void    handle_timer_expired(void *ctx);
                void    register_to_timer();
                int     add_data_reader(void* local_addr, void* shm_addr, int size);
                void*   pop_p_skt_stats(void* local_addr);


        private:
                void*  m_timer_handler;
                stats_read_map_t m_data_map;
};


#endif //STATS_DATA_READER_H
