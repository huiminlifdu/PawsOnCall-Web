package com.pawsoncall.web.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import com.pawsoncall.web.domain.User;

@Mapper
public interface UserMapper {

    @Select("select c_id as id, c_name as name, c_state as state, c_country as country from t_user where c_state = #{state}")
    User findByState(@Param("state") String state);

}
