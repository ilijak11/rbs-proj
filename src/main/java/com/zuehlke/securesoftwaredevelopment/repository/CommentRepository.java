package com.zuehlke.securesoftwaredevelopment.repository;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.controller.CommentController;
import com.zuehlke.securesoftwaredevelopment.domain.Comment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Repository
public class CommentRepository {

    private static final Logger LOG = LoggerFactory.getLogger(CommentRepository.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(CommentRepository.class);


    private DataSource dataSource;

    public CommentRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void create(Comment comment) {
        //String query = "insert into comments(giftId, userId, comment) values (" + comment.getGiftId() + ", " + comment.getUserId() + ", '" + comment.getComment() + "')";
        String query = "insert into comments(giftId, userId, comment) values (?, ?, ?)";

        try (Connection connection = dataSource.getConnection();
             //Statement statement = connection.createStatement();
             PreparedStatement preparedStatement = connection.prepareStatement(query);
        ) {
            preparedStatement.setInt(1, comment.getGiftId());
            preparedStatement.setInt(2, comment.getUserId());
            preparedStatement.setString(3, comment.getComment());
            preparedStatement.executeUpdate();
            auditLogger.audit("Commented: " + comment.getComment() + " on gift: " + comment.getGiftId());
            //statement.execute(query);
        } catch (SQLException e) {
            LOG.warn("Exception while creating comment: ", e);
            e.printStackTrace();
        }
    }

    public List<Comment> getAll(String giftId) {
        List<Comment> commentList = new ArrayList<>();
        String query = "SELECT giftId, userId, comment FROM comments WHERE giftId = " + giftId;
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(query)) {
            while (rs.next()) {
                commentList.add(new Comment(rs.getInt(1), rs.getInt(2), rs.getString(3)));
            }
        } catch (SQLException e) {
            LOG.warn("Exception while fetching all comments: ", e);
            e.printStackTrace();
        }
        return commentList;
    }
}
